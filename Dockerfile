FROM python:3.11-slim AS patched-base
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

FROM patched-base AS builder
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# ---------- итоговый образ ----------
FROM patched-base AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 appuser

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=appuser:appuser app/ ./app/
RUN chown appuser:appuser /app


RUN python -m pip uninstall -y setuptools wheel pip
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120", \
     "--worker-class", "uvicorn.workers.UvicornWorker", "app.main:app"]

