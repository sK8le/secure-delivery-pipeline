"""Startup behavior with unavailable and recovered database connections."""
import logging
import os
import secrets
import sqlite3

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import OperationalError, ProgrammingError

os.environ.setdefault("VULNTRACK_SECRET_KEY", secrets.token_hex(32))

from app import database  # noqa: E402


@pytest.fixture
def isolated_database(monkeypatch):
    engine = create_engine("sqlite://")
    monkeypatch.setattr(database, "engine", engine)
    yield engine
    engine.dispose()


def test_startup_creates_tables_when_database_is_available(isolated_database):
    database.init_db()
    assert set(inspect(isolated_database).get_table_names()) >= {
        "users", "assets", "vulnerabilities",
    }


def test_startup_recovers_after_temporary_connection_failures(monkeypatch):
    attempts = 0
    delays = []

    def connect():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise sqlite3.OperationalError("temporary connection failure")
        return sqlite3.connect(":memory:")

    engine = create_engine("sqlite://", creator=connect)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database.time, "sleep", delays.append)
    try:
        database.init_db()
        assert attempts == 3
        assert delays == [database.DB_STARTUP_RETRY_DELAY] * 2
        assert "users" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_permanent_connection_failure_stops_startup(monkeypatch, caplog):
    attempts = 0
    delays = []
    private_detail = "private connection details must not enter retry messages"

    def connect():
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError(private_detail)

    engine = create_engine("sqlite://", creator=connect)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database.time, "sleep", delays.append)
    try:
        with caplog.at_level(logging.WARNING, logger="vulntrack.database"):
            with pytest.raises(OperationalError):
                database.init_db()
        assert attempts == database.DB_STARTUP_ATTEMPTS
        assert len(delays) == database.DB_STARTUP_ATTEMPTS - 1
        assert "Database unavailable after" in caplog.text
        assert private_detail not in caplog.text
    finally:
        engine.dispose()


def test_schema_error_is_not_retried(isolated_database, monkeypatch):
    calls = []

    def fail_schema(**kwargs):
        calls.append(kwargs)
        raise ProgrammingError("CREATE TABLE", {}, RuntimeError("invalid schema"))

    monkeypatch.setattr(database.Base.metadata, "create_all", fail_schema)
    with pytest.raises(ProgrammingError):
        database.init_db()
    assert len(calls) == 1


def test_unexpected_connection_error_is_not_retried(monkeypatch):
    attempts = 0

    def connect():
        nonlocal attempts
        attempts += 1
        raise RuntimeError("unexpected startup error")

    engine = create_engine("sqlite://", creator=connect)
    monkeypatch.setattr(database, "engine", engine)
    try:
        with pytest.raises(RuntimeError, match="unexpected startup error"):
            database.init_db()
        assert attempts == 1
    finally:
        engine.dispose()
