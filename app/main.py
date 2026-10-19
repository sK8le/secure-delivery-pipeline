"""VulnTrack — веб-приложение «Трекер уязвимостей».

Аналитик регистрируется, импортирует отчёты сканеров и работает со списком
уязвимостей своей команды (CVE, CVSS, статус).
"""
import logging
import os
from contextlib import asynccontextmanager

import yaml
from cvss import CVSS3
from fastapi import FastAPI, Request, Depends, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.orm import Session

from app.config import COOKIE_SECURE, HOST, PORT
from app.database import get_db, init_db
from app.models import User, Asset, Vulnerability
from app.security import (
    SESSION_MAX_AGE, hash_password, verify_password, create_session_token, read_session_token,
)

BASE_DIR = os.path.dirname(__file__)
MAX_IMPORT_BYTES = 1024 * 1024  # 1 МиБ на файл отчёта

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("vulntrack")



@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="VulnTrack", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

LOGIN_ATTEMPTS = Counter("vulntrack_login_attempts_total", "Число попыток входа", ["result"])


# ---------------------------------------------------------------------------
# Аутентификация
# ---------------------------------------------------------------------------

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session")
    if not token:
        return None
    user_id = read_session_token(token)
    if user_id is None:
        return None
    return db.get(User, user_id)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/vulnerabilities")
    return RedirectResponse("/login")


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse(request, "register.html", {"request": request, "error": None})


@app.post("/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    team: str = Form("default"),
    db: Session = Depends(get_db),
):
    if db.query(User).filter_by(username=username).first():
        return templates.TemplateResponse(
            request, "register.html",
            {"request": request, "error": "Пользователь с таким именем уже существует"},
            status_code=400,
        )
    db.add(User(username=username, password_hash=hash_password(password), team=team))
    db.commit()
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.password_hash):
        LOGIN_ATTEMPTS.labels(result="success").inc()
        response = RedirectResponse("/vulnerabilities", status_code=303)
        response.set_cookie(
            key="session", value=create_session_token(user.id), max_age=SESSION_MAX_AGE,
            httponly=True, secure=COOKIE_SECURE, samesite="lax",
        )
        return response

    LOGIN_ATTEMPTS.labels(result="failure").inc()
    client = request.client.host if request.client else "-"
    logger.warning("login failed: user=%r ip=%s", username[:64], client)
    return templates.TemplateResponse(
        request, "login.html",
        {"request": request, "error": "Неверное имя пользователя или пароль"},
        status_code=401,
    )


@app.get("/logout")
def logout():
    response = RedirectResponse("/login")
    response.delete_cookie("session")
    return response


# ---------------------------------------------------------------------------
# Уязвимости (доступны только записи активов своей команды)
# ---------------------------------------------------------------------------

def team_vulnerabilities(db: Session, team: str):
    return db.query(Vulnerability).join(Asset, Vulnerability.asset_id == Asset.id).filter(Asset.team == team)


@app.get("/vulnerabilities", response_class=HTMLResponse)
def list_vulnerabilities(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    items = team_vulnerabilities(db, user.team).order_by(Vulnerability.created_at.desc()).all()
    return templates.TemplateResponse(
        request, "vulnerabilities.html", {"request": request, "user": user, "items": items}
    )


@app.get("/vulnerability/{vuln_id}", response_class=HTMLResponse)
def vulnerability_detail(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    item = team_vulnerabilities(db, user.team).filter(Vulnerability.id == vuln_id).first()
    if item is None:
        return templates.TemplateResponse(request, "404.html", {"request": request}, status_code=404)
    return templates.TemplateResponse(
        request, "vulnerability.html", {"request": request, "user": user, "item": item}
    )


@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = "", db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    results = []
    if q:
        like = f"%{q}%"
        results = (
            team_vulnerabilities(db, user.team)
            .filter((Vulnerability.title.ilike(like)) | (Vulnerability.cve_id.ilike(like)))
            .all()
        )
    return templates.TemplateResponse(
        request, "search.html", {"request": request, "user": user, "query": q, "results": results}
    )


# ---------------------------------------------------------------------------
# Инструменты
# ---------------------------------------------------------------------------

@app.get("/tools/cvss-calc", response_class=HTMLResponse)
def cvss_calc(request: Request, expr: str = "", db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    result = error = None
    if expr:
        try:
            result = CVSS3(expr).scores()[0]
        except Exception:
            error = "Некорректный CVSS-вектор"
    return templates.TemplateResponse(
        request, "cvss_calc.html",
        {"request": request, "user": user, "expr": expr, "result": result, "error": error},
    )


@app.post("/import", response_class=HTMLResponse)
async def import_scan(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")

    imported, error = 0, None
    raw = await file.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        error = "Файл слишком большой (максимум 1 МиБ)"
    else:
        try:
            data = yaml.safe_load(raw.decode("utf-8", errors="replace"))
            if not isinstance(data, list):
                raise ValueError("ожидается список записей")
            asset = Asset(name="Импортированный актив", team=user.team)
            db.add(asset)
            db.flush()
            for entry in data:
                if not isinstance(entry, dict):
                    raise ValueError("каждая запись должна быть словарём")
                db.add(Vulnerability(
                    cve_id=str(entry.get("cve_id", ""))[:32],
                    title=str(entry.get("title", "Без названия"))[:255],
                    description=str(entry.get("description", "")),
                    cvss_score=float(entry.get("cvss_score", 0.0)),
                    severity=str(entry.get("severity", "medium"))[:16],
                    asset_id=asset.id,
                    reported_by_id=user.id,
                ))
                imported += 1
            db.commit()
        except Exception:
            db.rollback()
            imported = 0
            logger.exception("import failed for user_id=%s", user.id)
            error = "Не удалось разобрать файл: проверьте формат отчёта"

    return templates.TemplateResponse(
        request, "import.html", {"request": request, "user": user, "imported": imported, "error": error}
    )


@app.get("/import", response_class=HTMLResponse)
def import_form(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse(
        request, "import.html", {"request": request, "user": user, "imported": None, "error": None}
    )


# ---------------------------------------------------------------------------
# Служебные маршруты
# ---------------------------------------------------------------------------

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return PlainTextResponse("Внутренняя ошибка сервера", status_code=500)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT)
