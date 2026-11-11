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


def test_login_rejects_nul_username_before_database(isolated_client):
    response = isolated_client.post('/login', data={'username': 'bad\x00name', 'password': secrets.token_urlsafe(18)})
    assert response.status_code == 422


def test_search_rejects_nul_query_before_database(isolated_client, tenant_records, authenticate):
    authenticate(tenant_records['alice'])
    assert isolated_client.get('/search', params={'q': 'bad\x00query'}).status_code == 422


@pytest.mark.parametrize('path', ['/register', '/login'])
@pytest.mark.parametrize('password', ['bad\x00password', 'a' * 4097], ids=['nul', 'oversized'])
def test_password_input_is_rejected_without_hashing(isolated_client, db_session, path, password):
    response = isolated_client.post(path, data={'username': 'new_account', 'password': password})
    assert response.status_code == 422
    assert db_session.query(User).count() == 0
