"""Operator-managed membership, including denial before assignment."""
import json
import secrets

import pytest

from app import manage
from app.models import User, Vulnerability
from app.security import create_session_token


@pytest.fixture
def pending_user(db_session, test_password_hash):
    user = User(username="pending_account", password_hash=test_password_hash, team="")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.mark.parametrize("path", [
    "/vulnerabilities", "/search?q=scopecheck", "/vulnerability/1",
    "/import", "/tools/cvss-calc",
])
def test_unassigned_account_cannot_use_team_routes(
    isolated_client, tenant_records, pending_user, authenticate, path,
):
    authenticate(pending_user)
    response = isolated_client.get(path)
    assert response.status_code == 403
    assert "BLUE_PRIVATE_RECORD" not in response.text
    assert "RED_PRIVATE_RECORD" not in response.text


def test_unassigned_account_cannot_import(
    isolated_client, tenant_records, pending_user, authenticate, db_session,
):
    authenticate(pending_user)
    count_before = db_session.query(Vulnerability).count()
    response = isolated_client.post(
        "/import", files={"file": ("scan.yaml", b"- title: forbidden import\n", "application/x-yaml")},
    )
    assert response.status_code == 403
    assert db_session.query(Vulnerability).count() == count_before


def test_registration_waits_for_operator_assignment(
    isolated_client, tenant_records, db_session,
):
    password = secrets.token_urlsafe(18)
    registration = isolated_client.post(
        "/register", data={"username": "new_analyst", "password": password, "team": "blue"},
        follow_redirects=False,
    )
    assert registration.status_code == 303
    user = db_session.query(User).filter_by(username="new_analyst").one()
    assert user.team == ""
    login = isolated_client.post(
        "/login", data={"username": "new_analyst", "password": password},
        follow_redirects=False,
    )
    assert login.status_code == 303
    assert login.headers["location"] == "/awaiting-team"
    assert isolated_client.get("/awaiting-team").status_code == 200
    assert isolated_client.get("/vulnerabilities").status_code == 403
    manage.assign_team(db_session, "new_analyst", "blue")
    response = isolated_client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "BLUE_PRIVATE_RECORD" in response.text
    assert "RED_PRIVATE_RECORD" not in response.text


def test_team_reassignment_changes_access_with_existing_session(
    isolated_client, tenant_records, db_session, authenticate,
):
    user = tenant_records["alice"]
    authenticate(user)
    manage.assign_team(db_session, user.username, "red")
    response = isolated_client.get("/vulnerabilities")
    assert response.status_code == 200
    assert "RED_PRIVATE_RECORD" in response.text
    assert "BLUE_PRIVATE_RECORD" not in response.text
    assert isolated_client.get(f"/vulnerability/{tenant_records['blue'].id}").status_code == 404


@pytest.mark.parametrize("team", ["", "   ", "a" * 65, "blue\nred", "\x1b[31mred"])
def test_invalid_operator_assignment_preserves_membership(db_session, tenant_records, team):
    user = tenant_records["alice"]
    with pytest.raises(ValueError):
        manage.assign_team(db_session, user.username, team)
    db_session.refresh(user)
    assert user.team == "blue"


def test_assignment_requires_existing_account(db_session):
    with pytest.raises(ValueError, match="Пользователь не найден"):
        manage.assign_team(db_session, "unknown_account", "blue")
    assert db_session.query(User).count() == 0


def test_operator_cli_assigns_team(db_session, pending_user, monkeypatch, capsys):
    monkeypatch.setattr(manage, "SessionLocal", lambda: db_session)
    manage.main(["assign-team", "--username", pending_user.username, "--team", "blue"])
    result = json.loads(capsys.readouterr().out)
    assert result == {"username": "pending_account", "team": "blue"}


def test_operator_inventory_excludes_password_hashes(db_session, tenant_records, monkeypatch, capsys):
    monkeypatch.setattr(manage, "SessionLocal", lambda: db_session)
    manage.main(["list-users"])
    output = capsys.readouterr().out
    rows = [json.loads(line) for line in output.splitlines()]
    assert {row["username"] for row in rows} == {"alice_blue", "bob_red", "colleague_blue"}
    assert all(set(row) == {"id", "username", "team"} for row in rows)
    assert "password_hash" not in output
