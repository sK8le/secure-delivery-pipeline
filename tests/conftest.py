"""Isolated database and HTTP fixtures for access-control scenarios."""
import os
import secrets

os.environ.setdefault("VULNTRACK_SECRET_KEY", secrets.token_hex(32))
os.environ.setdefault("VULNTRACK_COOKIE_SECURE", "false")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_vulntrack.db")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import Asset, User, Vulnerability
from app.security import create_session_token, hash_password


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


@pytest.fixture
def isolated_client(db_session):
    def override_database():
        yield db_session

    app.dependency_overrides[get_db] = override_database
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture(scope="session")
def test_password_hash():
    return hash_password(secrets.token_urlsafe(24))


@pytest.fixture
def tenant_records(db_session, test_password_hash):
    alice = User(username="alice_blue", password_hash=test_password_hash, team="blue")
    bob = User(username="bob_red", password_hash=test_password_hash, team="red")
    colleague = User(username="colleague_blue", password_hash=test_password_hash, team="blue")
    db_session.add_all([alice, bob, colleague])
    db_session.flush()
    blue_asset = Asset(name="Blue asset", team="blue")
    red_asset = Asset(name="Red asset", team="red")
    db_session.add_all([blue_asset, red_asset])
    db_session.flush()
    blue = Vulnerability(
        title="scopecheck BLUE_PRIVATE_RECORD", cve_id="CVE-TEST-BLUE",
        description="Blue team confidential description",
        asset_id=blue_asset.id, reported_by_id=alice.id,
    )
    red = Vulnerability(
        title="scopecheck RED_PRIVATE_RECORD", cve_id="CVE-TEST-RED",
        description="Red team confidential description",
        asset_id=red_asset.id, reported_by_id=bob.id,
    )
    db_session.add_all([blue, red])
    db_session.commit()
    return {"alice": alice, "bob": bob, "colleague": colleague, "blue": blue, "red": red}


@pytest.fixture
def authenticate(isolated_client):
    def sign_in(user):
        isolated_client.cookies.set("session", create_session_token(user.id))
    return sign_in
