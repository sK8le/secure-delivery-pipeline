"""Конфигурация приложения VulnTrack. Все параметры берутся из окружения."""
import os

# Ключ подписи сессий. Значения по умолчанию нет намеренно: без ключа
# приложение не запускается (отказ в безопасное состояние).
SECRET_KEY = os.environ["VULNTRACK_SECRET_KEY"]

# Флаг Secure у cookie сессии. По умолчанию включён; отключается только
# на стендах без TLS (локальный запуск, кластер разработки, DAST в CI).
COOKIE_SECURE = os.environ.get("VULNTRACK_COOKIE_SECURE", "true").lower() == "true"

# Строка подключения к БД. SQLite — для локальной разработки и тестов,
# в контейнере и кластере передаётся строка PostgreSQL.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntrack.db")

# Адрес сервера разработки (python -m app.main). В контейнере приложение
# запускает gunicorn с явным адресом привязки.
HOST = os.environ.get("VULNTRACK_HOST", "127.0.0.1")
PORT = int(os.environ.get("VULNTRACK_PORT", "8000"))
