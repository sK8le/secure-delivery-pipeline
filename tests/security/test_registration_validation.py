"""Reject values that PostgreSQL cannot store before committing registration."""
import secrets

import pytest

from app.models import User


@pytest.mark.parametrize("username", ["a" * 65, "я" * 65, "bad\x00name", "bad\nname"])
def test_invalid_username_does_not_reach_database(isolated_client, db_session, username):
    response = isolated_client.post(
        "/register", data={"username": username, "password": secrets.token_urlsafe(18)},
        follow_redirects=False,
    )
    assert response.status_code == 422
    assert db_session.query(User).count() == 0


@pytest.mark.parametrize("username", ["a" * 64, "я" * 64])
def test_username_at_database_limit_is_accepted(isolated_client, db_session, username):
    response = isolated_client.post(
        "/register", data={"username": username, "password": secrets.token_urlsafe(18)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert db_session.query(User).one().username == username
