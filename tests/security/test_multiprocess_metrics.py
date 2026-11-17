"""Verify that the HTTP metrics handler merges separate worker counters."""
import os
from pathlib import Path
import subprocess
import sys

from prometheus_client.parser import text_string_to_metric_families


def test_metrics_aggregate_independent_processes(tmp_path):
    env = {**os.environ, 'PROMETHEUS_MULTIPROC_DIR': str(tmp_path),
           'VULNTRACK_SECRET_KEY': 'test-key', 'DATABASE_URL': 'sqlite://'}
    root = Path(__file__).resolve().parents[2]

    def run_python(code, *args):
        return subprocess.check_output([sys.executable, '-c', code, *args], cwd=root,
                                       env=env, text=True, encoding='utf-8', timeout=30)

    count = 'from app.main import LOGIN_ATTEMPTS; import sys; LOGIN_ATTEMPTS.labels(result="failure").inc(int(sys.argv[1]))'
    run_python(count, '3')
    run_python(count, '5')
    report = run_python('from app.main import metrics; import sys; sys.stdout.buffer.write(metrics().body)')
    values = [sample.value for family in text_string_to_metric_families(report)
              for sample in family.samples if sample.name == 'vulntrack_login_attempts_total'
              and sample.labels == {'result': 'failure'}]
    assert values == [8.0]
