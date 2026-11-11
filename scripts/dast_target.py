"""Seed and verify an authenticated, disposable DAST target without logging cookies."""
import argparse
from html.parser import HTMLParser
from http.cookiejar import MozillaCookieJar
import json
from pathlib import Path
import re
import secrets
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener


class TargetError(ValueError):
    pass


def load_cookie_jar(path):
    jar = MozillaCookieJar(str(path))
    jar.load(ignore_discard=True, ignore_expires=True)
    # curl writes session-cookie expiry as 0; MozillaCookieJar treats it as 1970.
    for cookie in jar:
        if cookie.expires == 0:
            cookie.expires = None
            cookie.discard = True
    return jar


def target_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise TargetError("Target must be an HTTP(S) origin without credentials or a path")
    return value.rstrip("/")


class CardLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href", "")
        if tag == "a" and re.fullmatch(r"/vulnerability/[1-9][0-9]*", href):
            self.ids.append(int(href.rsplit("/", 1)[1]))


def request(client, target, path, checks, required_text=None, upload=None):
    headers = {}
    data = None
    if upload is not None:
        boundary = "dast" + secrets.token_hex(12)
        data = (f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="scan.yaml"\r\n'
                "Content-Type: application/x-yaml\r\n\r\n"
                f"{upload}\r\n--{boundary}--\r\n").encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    message = Request(target + path, data=data, headers=headers)
    try:
        response = client.open(message, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        status = response.code
        body = response.read(1024 * 1024).decode("utf-8", errors="replace")
        same_page = response.geturl() == target + path
    ok = status == 200 and same_page and (required_text is None or required_text in body)
    checks.append({"path": path, "method": message.get_method(), "status": status,
                   "no_redirect": same_page, "passed": ok})
    if not ok:
        raise TargetError(f"Target check failed: {message.get_method()} {path}, HTTP {status}")
    return body


def inspect_target(client, target, state, checks):
    for item in state["required"]:
        request(client, target, item["path"], checks, required_text=item["contains"])


def run(phase, target, username, cookie_file, state_file, output):
    checks = []
    result = {"phase": phase, "target": target, "username": username,
              "passed": False, "checks": checks}
    try:
        target = target_origin(target)
        jar = load_cookie_jar(cookie_file)
        if not any(cookie.name == "session" and cookie.value for cookie in jar):
            raise TargetError("Session cookie is missing")
        client = build_opener(HTTPCookieProcessor(jar))
        if phase == "before":
            marker = "DAST_" + secrets.token_hex(6)
            request(client, target, "/vulnerabilities", checks, required_text=username)
            payload = f"- title: {marker}\n  cve_id: DEMO-DAST\n  severity: low\n"
            request(client, target, "/import", checks, upload=payload)
            body = request(client, target, "/search?" + urlencode({"q": marker}), checks,
                           required_text=marker)
            links = CardLinks()
            links.feed(body)
            if len(links.ids) != 1:
                raise TargetError("The seeded search must identify exactly one card")
            required = [
                {"path": "/healthz", "contains": None},
                {"path": "/register", "contains": None},
                {"path": "/login", "contains": None},
                {"path": "/vulnerabilities", "contains": marker},
                {"path": "/search?" + urlencode({"q": marker}), "contains": marker},
                {"path": f"/vulnerability/{links.ids[0]}", "contains": marker},
                {"path": "/import", "contains": username},
                {"path": "/tools/cvss-calc", "contains": username},
            ]
            state = {"schema": 1, "target": target, "username": username,
                     "marker": marker, "required": required}
            inspect_target(client, target, state, checks)
            Path(state_file).write_text(json.dumps(state, indent=2), encoding="utf-8")
        else:
            state = json.loads(Path(state_file).read_text(encoding="utf-8"))
            if state["target"] != target or state["username"] != username:
                raise TargetError("Post-scan identity or target does not match the seed")
            inspect_target(client, target, state, checks)
        result.update(target=target, marker=state["marker"], passed=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Exception strings from HTTP or file libraries can contain private data.
        result["error"] = str(error) if isinstance(error, TargetError) else type(error).__name__
    Path(output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=["before", "after"])
    parser.add_argument("--target", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--cookie-file", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    return run(args.phase, args.target, args.username, args.cookie_file, args.state, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
