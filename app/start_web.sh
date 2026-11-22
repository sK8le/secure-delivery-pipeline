#!/bin/sh
set -eu

# /tmp is writable in the image and mounted as a pod-local emptyDir in Kubernetes.
# emptyDir survives container restarts, so remove the previous master's metrics.
export PROMETHEUS_MULTIPROC_DIR=/tmp/vulntrack-prometheus
mkdir -p -m 700 "$PROMETHEUS_MULTIPROC_DIR"
rm -f -- "$PROMETHEUS_MULTIPROC_DIR"/*.db

exec gunicorn --bind 0.0.0.0:8000 --workers 2 --timeout 120 \
    --config /app/app/gunicorn_conf.py \
    --worker-class uvicorn.workers.UvicornWorker app.main:app
