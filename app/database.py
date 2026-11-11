"""Подключение к базе данных через SQLAlchemy 2.0 (синхронный движок)."""
import logging
import time

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.exc import OperationalError

from app.config import DATABASE_URL

logger = logging.getLogger("vulntrack.database")

DB_STARTUP_ATTEMPTS = 12
DB_STARTUP_RETRY_DELAY = 2

if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
elif DATABASE_URL.startswith("postgresql"):
    # libpq bounds each connection attempt; Kubernetes bounds total startup time.
    connect_args = {"connect_timeout": 3}
else:
    connect_args = {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI-зависимость: одна сессия БД на один запрос."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def wait_for_database() -> None:
    """Retry temporary connection failures, then propagate the last error."""
    for attempt in range(1, DB_STARTUP_ATTEMPTS + 1):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            if attempt > 1:
                logger.info("Database connection recovered on startup attempt %s", attempt)
            return
        except OperationalError:
            # Do not log connection strings or exception details with credentials.
            if attempt == DB_STARTUP_ATTEMPTS:
                logger.error("Database unavailable after %s startup attempts", attempt)
                raise
            logger.warning(
                "Database unavailable at startup (attempt %s/%s); retrying in %ss",
                attempt, DB_STARTUP_ATTEMPTS, DB_STARTUP_RETRY_DELAY,
            )
            time.sleep(DB_STARTUP_RETRY_DELAY)


def init_db() -> None:
    from app import models  # noqa: F401

    wait_for_database()
    try:
        Base.metadata.create_all(bind=engine)
    except OperationalError as exc:
        if "already exists" not in str(exc):
            raise
