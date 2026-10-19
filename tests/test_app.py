"""Функциональные тесты VulnTrack, включая регрессионные тесты мер защиты."""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_vulntrack.db")
os.environ.setdefault("VULNTRACK_COOKIE_SECURE", "false")  # TestClient работает по HTTP

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.database import init_db  # noqa: E402

init_db()

REPORT = b"""- cve_id: CVE-2024-0001
  title: Test finding
  cvss_score: 7.5
  severity: high
"""


def new_user(team: str) -> TestClient:
    """Регистрирует уникального пользователя и возвращает клиент с его сессией."""
    client = TestClient(app)
    name = f"u_{uuid.uuid4().hex[:8]}"
    client.post("/register", data={"username": name, "password": "s3cret-pass", "team": team})
    r = client.post("/login", data={"username": name, "password": "s3cret-pass"}, follow_redirects=False)
    assert r.status_code == 303
    return client


def test_protected_route_requires_login():
    r = TestClient(app).get("/vulnerabilities", follow_redirects=False)
    assert r.status_code in (302, 303, 307)
    assert r.headers["location"] == "/login"


def test_wrong_password_rejected():
    r = TestClient(app).post("/login", data={"username": "nobody", "password": "wrong"})
    assert r.status_code == 401


def test_session_cookie_flags():
    client = TestClient(app)
    name = f"u_{uuid.uuid4().hex[:8]}"
    client.post("/register", data={"username": name, "password": "s3cret-pass"})
    r = client.post("/login", data={"username": name, "password": "s3cret-pass"}, follow_redirects=False)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie


def test_security_headers_present():
    r = TestClient(app).get("/login")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_search_output_is_escaped():
    client = new_user("blue")
    r = client.get("/search", params={"q": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_other_team_cannot_read_record():
    owner = new_user("red")
    r = owner.post("/import", files={"file": ("r.yaml", REPORT, "application/x-yaml")})
    assert "Импортировано записей: 1" in r.text
    listing = owner.get("/vulnerabilities").text
    start = listing.index('href="/vulnerability/') + len('href="')
    vuln_path = listing[start:listing.index('"', start)]

    assert owner.get(vuln_path).status_code == 200
    stranger = new_user("green")
    assert stranger.get(vuln_path).status_code == 404
    assert vuln_path not in stranger.get("/vulnerabilities").text


def test_cvss_calc_does_not_evaluate_code():
    client = new_user("blue")
    r = client.get("/tools/cvss-calc", params={"expr": "__import__('os').getcwd()"})
    assert "Некорректный CVSS-вектор" in r.text


def test_import_rejects_malformed_report_without_details():
    client = new_user("blue")
    r = client.post("/import", files={"file": ("r.yaml", b"!!python/object/apply:os.system ['id']", "text/plain")})
    assert "Не удалось разобрать файл" in r.text
    assert "python/object" not in r.text
