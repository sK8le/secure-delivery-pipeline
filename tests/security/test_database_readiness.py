"""Readiness checks database access, while liveness remains independent."""

from sqlalchemy import text


def test_empty_database_with_schema_is_ready(isolated_client):
    response = isolated_client.get('/readyz')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}


def test_missing_application_table_fails_readiness_but_not_liveness(isolated_client, db_session):
    db_session.execute(text('DROP TABLE users'))
    db_session.commit()

    response = isolated_client.get('/readyz')
    assert response.status_code == 503
    assert response.json() == {'status': 'unavailable'}
    assert isolated_client.get('/healthz').status_code == 200
