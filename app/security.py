"""Хеширование паролей и подписанные токены сессии."""
from itsdangerous import URLSafeTimedSerializer, BadSignature
from passlib.hash import bcrypt

from app.config import SECRET_KEY

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="vulntrack-session")

SESSION_MAX_AGE = 60 * 60 * 8  # 8 часов


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.verify(password, password_hash)


def create_session_token(user_id: int) -> str:
    return _serializer.dumps({"user_id": user_id})


def read_session_token(token: str, max_age: int = SESSION_MAX_AGE):
    try:
        data = _serializer.loads(token, max_age=max_age)
        return data.get("user_id")
    except BadSignature:
        return None
