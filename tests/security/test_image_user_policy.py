"""Image-user admission policy, including Docker's omitted User key."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts import check_image_user


@pytest.mark.parametrize('config', [{}, {'User': None}, {'User': ''}, {'User': '0'},
                                   {'User': 'root'}, {'User': '0:10001'},
                                   {'User': '000'}, {'User': '-1'}, {'User': '4294967295'}])
def test_unsafe_or_missing_default_user_is_blocked(config):
    assert check_image_user.assess_image({'Config': config})['decision'] == 'blocked'


@pytest.mark.parametrize('user', ['10001', '10001:10001', '10001:0'])
def test_positive_numeric_uid_is_allowed(user):
    report = check_image_user.assess_image({'Id': 'test-id', 'Config': {'User': user}})
    assert report['decision'] == 'passed'
    assert report['uid'] == 10001


@pytest.mark.parametrize('config', [{'User': 'appuser'}, {'User': '10001:root'},
                                   {'User': '10001:4294967295'}, {'User': ' 10001'}])
def test_unsupported_identity_is_blocked(config):
    assert check_image_user.assess_image({'Config': config})['decision'] == 'blocked'


@pytest.mark.parametrize('response,code,decision', [
    ([{'Config': {'User': '10001'}}], 0, 'passed'),
    ([{'Config': {}}], 1, 'blocked'),
    ([{'Config': {'User': '0'}}], 1, 'blocked'),
    ([], 2, 'error'),
    ([{'Config': None}], 2, 'error'),
    ([{'Config': {'User': 10001}}], 2, 'error'),
])
def test_cli_report_and_exit_code(monkeypatch, tmp_path, response, code, decision):
    def inspect(args, **kwargs):
        assert args == ['docker', 'image', 'inspect', 'vulntrack:ci']
        return SimpleNamespace(stdout=json.dumps(response))
    monkeypatch.setattr(check_image_user.subprocess, 'run', inspect)
    output = tmp_path / 'report.json'
    assert check_image_user.main(['--output', str(output)]) == code
    assert json.loads(output.read_text())['decision'] == decision


def test_docker_failure_is_an_error_not_a_policy_finding(monkeypatch, tmp_path):
    def unavailable(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ['docker'])
    monkeypatch.setattr(check_image_user.subprocess, 'run', unavailable)
    output = tmp_path / 'error.json'
    assert check_image_user.main(['--output', str(output)]) == 2
    assert json.loads(output.read_text())['decision'] == 'error'
