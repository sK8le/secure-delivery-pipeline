"""Check a local app through HTTP and the operator interface.

Run inside the application container, with its database configuration.
Creates uniquely named synthetic users/data and removes those records on exit.
"""
import argparse
from http.cookiejar import CookieJar
import json
import secrets
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

from app.database import SessionLocal
from app.manage import assign_team
from app.models import Asset, User, Vulnerability


class CheckFailure(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Invalid local port")
    base_url = f"http://127.0.0.1:{args.port}"
    nonce = secrets.token_hex(6)
    marker = f"VT_ACCEPT_{nonce}"
    teams = {"blue": f"proof_{nonce}_blue", "red": f"proof_{nonce}_red"}
    owned_users = {}
    checks = []
    failure = None
    cleanup_ok = False

    def check(name, condition, actual=None):
        checks.append({"check": name, "passed": bool(condition), "actual": actual})
        if not condition:
            raise CheckFailure(name)

    def browser():
        return build_opener(HTTPCookieProcessor(CookieJar()))

    def request(client, path, form=None, upload=None):
        data = None
        headers = {}
        if form is not None:
            data = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if upload is not None:
            boundary = "vtproof" + secrets.token_hex(12)
            data = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="scan.yaml"\r\n'
                "Content-Type: application/x-yaml\r\n\r\n"
                f"{upload}\r\n--{boundary}--\r\n"
            ).encode()
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        message = Request(base_url + path, data=data, headers=headers)
        try:
            with client.open(message, timeout=20) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except HTTPError as response:
            return response.code, response.read().decode("utf-8", errors="replace")

    with SessionLocal() as db:
        def register(role, forged_team=None):
            username = f"proof_{nonce}_{role}"
            password = secrets.token_urlsafe(24)
            form = {"username": username, "password": password}
            if forged_team:
                form["team"] = forged_team
            client = browser()
            status, _ = request(client, "/register", form=form)
            # urllib follows the registration redirect to the login page.
            if status != 200:
                raise CheckFailure(f"registration_http_{role}_{status}")
            user = db.query(User).filter(User.username == username).first()
            if user is None:
                raise CheckFailure(f"registration_missing_{role}")
            owned_users[user.id] = username
            check(f"registration_pending_{role}", user.team == "")
            status, _ = request(client, "/login", form={"username": username, "password": password})
            check(f"login_{role}", status == 200, status)
            return client, user

        try:
            blue_client, blue_user = register("blue")
            red_client, red_user = register("red")
            status, _ = request(blue_client, "/vulnerabilities")
            check("pending_account_denied", status == 403, status)
            assign_team(db, blue_user.username, teams["blue"])
            assign_team(db, red_user.username, teams["red"])
            for role, client in (("blue", blue_client), ("red", red_client)):
                title = marker + "_" + role.upper()
                payload = (
                    f"- title: {title}\n  cve_id: CVE-TEST-{nonce}-{role[0]}\n"
                    f"  team: {teams['red' if role == 'blue' else 'blue']}\n"
                    f"  reported_by_id: {red_user.id if role == 'blue' else blue_user.id}\n"
                )
                status, _ = request(client, "/import", upload=payload)
                check(f"import_http_{role}", status == 200, status)
            records = {
                role: db.query(Vulnerability).filter(
                    Vulnerability.title == marker + "_" + role.upper(),
                ).one()
                for role in ("blue", "red")
            }
            check("import_team_is_server_assigned", records["blue"].asset.team == teams["blue"])
            check("import_reporter_is_server_assigned", records["blue"].reported_by_id == blue_user.id)
            for path, name in (("/vulnerabilities", "list"), ("/search?" + urlencode({"q": marker}), "search")):
                status, body = request(blue_client, path)
                check(f"{name}_own_visible", status == 200 and marker + "_BLUE" in body, status)
                check(f"{name}_foreign_hidden", marker + "_RED" not in body)
            status, _ = request(blue_client, f"/vulnerability/{records['red'].id}")
            check("foreign_detail_denied", status == 404, status)
            outsider_client, outsider = register("outsider", forged_team=teams["blue"])
            status, _ = request(outsider_client, f"/vulnerability/{records['blue'].id}")
            check("forged_membership_denied", status == 403, status)
            assign_team(db, outsider.username, teams["blue"])
            status, body = request(outsider_client, f"/vulnerability/{records['blue'].id}")
            check("operator_assignment_grants_team_access", status == 200 and marker + "_BLUE" in body, status)
            assign_team(db, outsider.username, teams["red"])
            status, _ = request(outsider_client, f"/vulnerability/{records['blue'].id}")
            check("reassignment_revokes_previous_team_access", status == 404, status)
            status, body = request(outsider_client, f"/vulnerability/{records['red'].id}")
            check("reassignment_grants_new_team_access", status == 200 and marker + "_RED" in body, status)
        except CheckFailure as exc:
            failure = {"kind": "assertion_failure", "check": str(exc)}
        except Exception as exc:
            # Raw exceptions may contain database connection details.
            failure = {"kind": "execution_error", "type": type(exc).__name__}
        finally:
            db.rollback()
            try:
                # Delete only the accounts this run successfully registered.
                for user_id, username in owned_users.items():
                    user = db.get(User, user_id)
                    if user is not None:
                        if user.username != username:
                            raise RuntimeError("Refusing to remove an unexpected account")
                        db.delete(user)
                db.flush()
                # Synthetic teams have unique names generated by this run.
                for asset in db.query(Asset).filter(Asset.team.in_(list(teams.values()))):
                    if db.query(Vulnerability).filter(Vulnerability.asset_id == asset.id).first():
                        raise RuntimeError("Refusing to remove an asset with remaining records")
                    db.delete(asset)
                db.commit()
                cleanup_ok = True
            except Exception as exc:
                db.rollback()
                failure = failure or {"kind": "cleanup_error", "type": type(exc).__name__}
    result = {"run_id": nonce, "checks": checks, "cleanup_ok": cleanup_ok, "failure": failure}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if failure is None and cleanup_ok else 1)


if __name__ == "__main__":
    main()
