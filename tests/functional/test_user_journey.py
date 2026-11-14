"""Positive user journeys shared by the baseline and secured CI variants.

Security regressions, hostile inputs and cross-team access are tested separately.
"""
import secrets

from app.manage import assign_team
from app.models import Vulnerability


def sign_in_member(client, db):
    username = "functional_user"
    password = secrets.token_urlsafe(20)
    response = client.post(
        "/register", data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assign_team(db, username, "functional_team")
    response = client.post(
        "/login", data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/vulnerabilities"
    return username


def test_health_endpoint(isolated_client):
    response = isolated_client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_public_forms_render(isolated_client):
    for path in ("/register", "/login"):
        response = isolated_client.get(path)
        assert response.status_code == 200
        assert 'name="username"' in response.text
        assert 'name="password"' in response.text


def test_registration_login_and_logout(isolated_client, db_session):
    username = sign_in_member(isolated_client, db_session)
    response = isolated_client.get("/vulnerabilities")
    assert response.status_code == 200
    assert username in response.text
    response = isolated_client.get("/logout", follow_redirects=False)
    assert response.status_code in (302, 303, 307)
    assert response.headers["location"] == "/login"
    assert isolated_client.get("/login").status_code == 200


def test_import_list_search_and_detail(isolated_client, db_session):
    sign_in_member(isolated_client, db_session)
    report = b"""- cve_id: DEMO-FUNCTIONAL-001
  title: Functional import example
  cvss_score: 7.5
  severity: high
"""
    response = isolated_client.post(
        "/import", files={"file": ("report.yaml", report, "application/x-yaml")},
    )
    assert response.status_code == 200
    assert "Импортировано записей: 1" in response.text
    item = db_session.query(Vulnerability).filter_by(cve_id="DEMO-FUNCTIONAL-001").one()
    for path in ("/vulnerabilities", f"/vulnerability/{item.id}"):
        response = isolated_client.get(path)
        assert response.status_code == 200
        assert "Functional import example" in response.text
    response = isolated_client.get("/search", params={"q": "DEMO-FUNCTIONAL-001"})
    assert response.status_code == 200
    assert "Functional import example" in response.text


def test_cvss_base_score(isolated_client, db_session):
    sign_in_member(isolated_client, db_session)
    response = isolated_client.get("/tools/cvss-calc", params={
        "expr": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    })
    assert response.status_code == 200
    assert "Результат: 9.8" in response.text
