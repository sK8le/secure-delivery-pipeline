"""Exercise the delivery decision on findings and failed/incomplete scan evidence."""
import copy
from contextlib import nullcontext
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import re
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.request import Request

import pytest

from scripts import dast_gate, dast_target


@pytest.fixture
def evidence():
    marker = "DAST_012345abcdef"
    target = "http://127.0.0.1:30080"
    paths = ["/healthz", "/register", "/login", "/vulnerabilities", "/import", "/tools/cvss-calc",
             "/search?q=" + marker, "/vulnerability/1"]
    state = {"schema": 1, "target": target, "marker": marker, "username": "scanner",
             "required": [{"path": p, "contains": None} for p in paths]}
    checks = [{"path": p, "method": "GET", "status": 200,
               "no_redirect": True, "passed": True} for p in paths]
    before = {"phase": "before", "target": target, "marker": marker,
              "username": "scanner", "passed": True, "checks": checks}
    after = dict(copy.deepcopy(before), phase="after")
    observation = {"schema": 1, "target": target, "marker": marker, "zap_version": "test",
                   "messages": 8, "missing_urls": [], "server_errors": [],
                   "active_scan_complete": True, "passive_remaining": 0}
    report = {"@version": "test", "site": [{"@name": target, "alerts": []}]}
    return dict(report=report, state=state, before=before, after=after,
                observation=observation, exit_code=0, rules={"10010": "FAIL", "40018": "FAIL"})


def alert(plugin="40018", risk="3"):
    return {"pluginid": plugin, "riskcode": risk, "name": "Controlled test finding",
            "instances": [{"uri": "http://127.0.0.1:30080/search?q=test"}]}


def test_clean_complete_scan_passes(evidence):
    assert dast_gate.analyze(**evidence)["decision"] == "passed"


@pytest.mark.parametrize("rule", [None, "WARN", "IGNORE"])
def test_unknown_high_is_blocked_even_outside_fail_list(evidence, rule):
    evidence["report"]["site"][0]["alerts"] = [alert("999999")]
    if rule:
        evidence["rules"]["999999"] = rule
    assert dast_gate.analyze(**evidence)["decision"] == "blocked"


def test_sql_injection_is_blocked(evidence):
    evidence["report"]["site"][0]["alerts"] = [alert()]
    assert dast_gate.analyze(**evidence)["blocking_findings"][0]["plugin_id"] == "40018"


def test_explicit_fail_blocks_even_low_risk(evidence):
    evidence["report"]["site"][0]["alerts"] = [alert("10010", "1")]
    assert dast_gate.analyze(**evidence)["decision"] == "blocked"


def test_nonblocking_findings_stay_in_report(evidence):
    evidence["report"]["site"][0]["alerts"] = [alert("10202", "2")]
    decision = dast_gate.analyze(**evidence)
    assert decision["decision"] == "passed"
    assert decision["nonblocking_findings"][0]["risk_code"] == 2


@pytest.mark.parametrize("change", ["before500", "after500", "redirect", "empty_checks",
                                    "wrong_identity", "wrong_marker", "missing_url",
                                    "server500", "active_incomplete", "passive_incomplete",
                                    "scanner_error", "unknown_exit", "unexplained_fail"])
def test_invalid_scan_never_passes(evidence, change):
    if change in {"before500", "after500"}:
        phase = "before" if change.startswith("before") else "after"
        evidence[phase]["checks"][0].update(status=500, passed=False)
        evidence[phase]["passed"] = False
    elif change == "redirect":
        evidence["before"]["checks"][0]["no_redirect"] = False
    elif change == "empty_checks":
        evidence["after"]["checks"] = []
    elif change == "wrong_identity":
        evidence["after"]["username"] = "somebody-else"
    elif change == "wrong_marker":
        evidence["observation"]["marker"] = "DAST_ffffffffffff"
    elif change == "missing_url":
        evidence["observation"]["missing_urls"] = ["/vulnerability/1"]
    elif change == "server500":
        evidence["observation"]["server_errors"] = [{"path": "/register", "status": 500}]
    elif change == "active_incomplete":
        evidence["observation"]["active_scan_complete"] = False
    elif change == "passive_incomplete":
        evidence["observation"]["passive_remaining"] = 10
    elif change == "scanner_error":
        evidence["exit_code"] = 3
    elif change == "unknown_exit":
        evidence["exit_code"] = 137
    elif change == "unexplained_fail":
        evidence["exit_code"] = 1
    with pytest.raises((ValueError, KeyError, TypeError)) if change == "wrong_marker" else nullcontext():
        result = dast_gate.analyze(**evidence)
        assert result["decision"] == "scan_error"


def write_evidence(directory, evidence):
    for key, name in (("report", "zap.json"), ("state", "state.json"),
                      ("before", "before.json"), ("after", "after.json"),
                      ("observation", "observation.json")):
        (directory / name).write_text(json.dumps(evidence[key]), encoding="utf-8")
    (directory / "exit-code.txt").write_text(str(evidence["exit_code"]), encoding="utf-8")
    rules = directory / "rules.tsv"
    rules.write_text("10010\tFAIL\tHttpOnly\n40018\tFAIL\tSQL injection\n", encoding="utf-8")
    return rules


@pytest.mark.parametrize("broken", ["missing", "bad_json", "no_site", "wrong_site", "no_risk"])
def test_missing_or_malformed_report_fails_closed(evidence, tmp_path, broken):
    rules = write_evidence(tmp_path, evidence)
    report = tmp_path / "zap.json"
    if broken == "missing":
        report.unlink()
    elif broken == "bad_json":
        report.write_text("{", encoding="utf-8")
    else:
        if broken == "no_site":
            evidence["report"]["site"] = []
        elif broken == "wrong_site":
            evidence["report"]["site"][0]["@name"] = "http://different.invalid"
        elif broken == "no_risk":
            finding = alert()
            finding.pop("riskcode")
            evidence["report"]["site"][0]["alerts"] = [finding]
        report.write_text(json.dumps(evidence["report"]), encoding="utf-8")
    assert dast_gate.evaluate_files(tmp_path, rules)["decision"] == "scan_error"


def test_cli_exit_and_saved_decision(evidence, tmp_path):
    rules = write_evidence(tmp_path, evidence)
    output = tmp_path / "gate.json"
    args = ["--directory", str(tmp_path), "--rules", str(rules), "--output", str(output)]
    assert dast_gate.main(args) == 0
    evidence["report"]["site"][0]["alerts"] = [alert()]
    write_evidence(tmp_path, evidence)
    assert dast_gate.main(args) == 1
    assert json.loads(output.read_text(encoding="utf-8"))["decision"] == "blocked"


class Response:
    def __init__(self, url, code=200, body=b"scanner DAST_012345abcdef"):
        self.url, self.code, self.body = url, code, body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, _limit):
        return self.body


@pytest.mark.parametrize("mode", ["500", "login_redirect", "wrong_body"])
def test_preflight_rejects_false_green_responses(mode):
    url = "http://127.0.0.1:30080/vulnerabilities"
    response = Response(url)
    if mode == "500":
        response.code = 500
    elif mode == "login_redirect":
        response.url = "http://127.0.0.1:30080/login"
    else:
        response.body = b"Login page"
    client = SimpleNamespace(open=lambda *_args, **_kwargs: response)
    with pytest.raises(dast_target.TargetError):
        dast_target.request(client, "http://127.0.0.1:30080", "/vulnerabilities", [],
                            required_text="DAST_012345abcdef")


@pytest.mark.parametrize("expiry,secure,domain,expected", [
    ("0", "FALSE", "127.0.0.1", True),
    ("", "FALSE", "127.0.0.1", True),
    ("1", "FALSE", "127.0.0.1", False),
    ("4102444800", "FALSE", "127.0.0.1", True),
    ("0", "TRUE", "127.0.0.1", False),
    ("0", "FALSE", "other.invalid", False),
], ids=["curl-session", "mozilla-session", "really-expired", "future-expiry",
        "secure-http-denied", "foreign-domain-denied"])
def test_curl_cookie_jar_session_and_expiry_rules(tmp_path, expiry, secure, domain, expected):
    cookie_file = tmp_path / "curl-cookie.txt"
    cookie_file.write_text(
        "# Netscape HTTP Cookie File\n"
        f"#HttpOnly_{domain}\tFALSE\t/\t{secure}\t{expiry}\tsession\texample\n",
        encoding="utf-8",
    )
    jar = dast_target.load_cookie_jar(cookie_file)
    request = Request("http://127.0.0.1:30080/vulnerabilities")
    jar.add_cookie_header(request)
    assert request.has_header("Cookie") is expected


@pytest.mark.parametrize("address,allowed", [
    ("zap", True),
    ("localhost", True),
    ("zap.attacker.invalid", False),
    ("localhost.attacker.invalid", False),
    ("127.0.0.1", True),
    ("::1", True),
    ("0:0:0:0:0:0:0:1", True),
    ("127.0.0.10", False),
    ("127x0x0x1", False),
    ("192.168.49.2", False),
    ("2001:db8::1", False),
    ("0.0.0.0", False),
])
def test_scanner_api_allows_local_client_and_packaged_api_host(address, allowed):
    path = Path(__file__).resolve().parents[2] / ".github/workflows/security.yml"
    workflow = path.read_text(encoding="utf-8")
    pattern = re.search(r"api[.]addrs[.]addr[.]name=(\S+) -config api[.]addrs[.]addr[.]regex=true", workflow)
    assert pattern is not None
    assert bool(re.fullmatch(pattern.group(1), address)) is allowed


def test_zap_hooks_load_with_packaged_scan_loader(evidence, tmp_path, monkeypatch):
    # ZAP uses ModuleType + SourceFileLoader.exec_module, without setting __file__.
    path = Path(__file__).resolve().parents[2] / ".zap" / "scan_hooks.py"
    reports = tmp_path / "dast-reports"
    reports.mkdir()
    (reports / "state.json").write_text(json.dumps(evidence["state"]), encoding="utf-8")
    monkeypatch.chdir(reports)
    loader = SourceFileLoader("zap_hooks", str(path))
    hooks = ModuleType(loader.name)
    loader.exec_module(hooks)
    target = evidence["state"]["target"]
    reached = []
    messages = [{"requestHeader": f"GET {p['path']} HTTP/1.1\r\n",
                 "responseHeader": "HTTP/1.1 200 OK\r\n"}
                for p in evidence["state"]["required"]]
    zap = SimpleNamespace(
        urlopen=lambda url: reached.append(url) or "",
        core=SimpleNamespace(version="test", messages=lambda **_: messages),
        ascan=SimpleNamespace(scans=[{"progress": "100"}]),
        pscan=SimpleNamespace(records_to_scan="0"),
    )
    hooks.zap_started(zap, target)
    hooks.zap_pre_shutdown(zap)
    assert reached == [target + item["path"] for item in evidence["state"]["required"]]
    evidence["observation"] = json.loads((reports / "observation.json").read_text(encoding="utf-8"))
    assert dast_gate.analyze(**evidence)["decision"] == "passed"


def test_zap_history_catches_500_without_alert(evidence):
    path = Path(__file__).resolve().parents[2] / ".zap" / "scan_hooks.py"
    spec = importlib.util.spec_from_file_location("vulntrack_zap_hooks", path)
    hooks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hooks)
    target = evidence["state"]["target"]
    messages = [{"requestHeader": f"GET {p['path']} HTTP/1.1\r\n",
                 "responseHeader": "HTTP/1.1 200 OK\r\n"}
                for p in evidence["state"]["required"]]
    messages.append({"requestHeader": "POST /register HTTP/1.1\r\n",
                     "responseHeader": "HTTP/1.1 500 Internal Server Error\r\n"})
    zap = SimpleNamespace(core=SimpleNamespace(version="test", messages=lambda **_: messages),
                          ascan=SimpleNamespace(scans=[{"progress": "100"}]),
                          pscan=SimpleNamespace(records_to_scan="0"))
    observation = hooks.observe(zap, evidence["state"])
    assert observation["missing_urls"] == []
    assert observation["server_errors"] == [{"method": "POST", "path": "/register", "status": 500}]
    evidence["observation"] = observation
    assert dast_gate.analyze(**evidence)["decision"] == "scan_error"
