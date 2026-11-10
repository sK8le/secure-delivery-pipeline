"""Security acceptance scenarios for the existing team data model."""
import secrets

import pytest

from app.models import User, Vulnerability
from app.security import create_session_token


@pytest.mark.parametrize("path", [
    "/vulnerabilities", "/search?q=scopecheck", "/vulnerability/1", "/import",
])
def test_anonymous_user_cannot_read_team_data(isolated_client, path):
    response = isolated_client.get(path, follow_redirects=False)
    assert response.status_code in (302, 303, 307)
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize("suffix", ["", "?team=red"])
def test_list_excludes_other_team(isolated_client, tenant_records, authenticate, suffix):
    authenticate(tenant_records["alice"])
    response = isolated_client.get("/vulnerabilities" + suffix)
    assert response.status_code == 200
    assert "BLUE_PRIVATE_RECORD" in response.text
    assert "RED_PRIVATE_RECORD" not in response.text


@pytest.mark.parametrize("query", ["scopecheck", "CVE-TEST", "%"])
def test_search_excludes_other_team(isolated_client, tenant_records, authenticate, query):
    authenticate(tenant_records["alice"])
    response = isolated_client.get("/search", params={"q": query, "team": "red"})
    assert response.status_code == 200
    assert "BLUE_PRIVATE_RECORD" in response.text
    assert "RED_PRIVATE_RECORD" not in response.text


def test_detail_denies_other_team(isolated_client, tenant_records, authenticate):
    authenticate(tenant_records["alice"])
    response = isolated_client.get(f"/vulnerability/{tenant_records['red'].id}")
    assert response.status_code == 404
    assert "RED_PRIVATE_RECORD" not in response.text


def test_colleague_can_read_same_team_record(isolated_client, tenant_records, authenticate):
    authenticate(tenant_records["colleague"])
    response = isolated_client.get(f"/vulnerability/{tenant_records['blue'].id}")
    assert response.status_code == 200
    assert "BLUE_PRIVATE_RECORD" in response.text


def test_registration_cannot_claim_existing_team(isolated_client, tenant_records, db_session):
    password = secrets.token_urlsafe(18)
    response = isolated_client.post(
        "/register",
        data={"username": "outsider", "password": password, "team": "blue"},
        follow_redirects=False,
    )
    assert response.status_code in (303, 400, 403)
    if response.status_code != 303:
        assert db_session.query(User).filter_by(username="outsider").first() is None
        return
    outsider = db_session.query(User).filter_by(username="outsider").one()
    assert outsider.team != tenant_records["alice"].team
    isolated_client.cookies.set("session", create_session_token(outsider.id))
    detail = isolated_client.get(f"/vulnerability/{tenant_records['blue'].id}")
    assert detail.status_code in (403, 404)
    assert "BLUE_PRIVATE_RECORD" not in detail.text


def test_invalid_session_cannot_read_team_data(isolated_client, tenant_records):
    isolated_client.cookies.set("session", secrets.token_urlsafe(32))
    response = isolated_client.get("/vulnerabilities", follow_redirects=False)
    assert response.status_code in (302, 303, 307)
    assert response.headers["location"] == "/login"


def test_import_assigns_team_and_reporter_on_server(
    isolated_client, tenant_records, authenticate, db_session,
):
    authenticate(tenant_records["alice"])
    payload = (
        "- title: IMPORT_SCOPE_MARKER\n"
        "  team: red\n"
        "  reported_by_id: " + str(tenant_records["bob"].id) + "\n"
        "  asset_id: " + str(tenant_records["red"].asset_id) + "\n"
    )
    response = isolated_client.post(
        "/import", files={"file": ("scan.yaml", payload.encode(), "application/x-yaml")},
    )
    assert response.status_code == 200
    imported = db_session.query(Vulnerability).filter_by(title="IMPORT_SCOPE_MARKER").one()
    assert imported.asset.team == tenant_records["alice"].team
    assert imported.reported_by_id == tenant_records["alice"].id
