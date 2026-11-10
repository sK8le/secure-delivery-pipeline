"""Fail delivery on High risk, explicit FAIL rules, or invalid scan evidence."""
import argparse
import json
from pathlib import Path
import re


def read_rules(path):
    rules = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        plugin, action, _ = line.split("\t", 2)
        if (not plugin.isdigit() or plugin in rules
                or action not in {"PASS", "IGNORE", "INFO", "WARN", "FAIL"}):
            raise ValueError("Invalid or duplicate ZAP rule")
        rules[plugin] = action
    if not rules:
        raise ValueError("Empty rule policy")
    return rules


def analyze(report, state, before, after, observation, exit_code, rules):
    errors = []
    findings = []
    warnings = []
    target, marker = state["target"], state["marker"]
    if state["schema"] != 1 or not re.fullmatch(r"DAST_[0-9a-f]{12}", marker):
        raise ValueError("Invalid seed state")
    required = {entry["path"] for entry in state["required"]}
    if (not {"/healthz", "/login", "/register", "/vulnerabilities", "/import", "/tools/cvss-calc"} <= required
            or f"/search?q={marker}" not in required
            or not any(re.fullmatch(r"/vulnerability/[1-9][0-9]*", path) for path in required)):
        raise ValueError("Incomplete required target routes")
    for phase, evidence in (("before", before), ("after", after)):
        if (evidence["phase"] != phase or evidence["passed"] is not True
                or evidence["target"] != target or evidence["marker"] != marker
                or evidence["username"] != state["username"]):
            errors.append(f"{phase}: target or authentication check failed")
        checks = evidence["checks"]
        if (not isinstance(checks, list) or not checks
                or not all(c["passed"] is True and c["status"] == 200
                           and c["no_redirect"] is True for c in checks)
                or not required <= {c["path"] for c in checks if c["method"] == "GET"}):
            errors.append(f"{phase}: incomplete or unsuccessful route checks")
    if (observation["schema"] != 1 or observation["target"] != target
            or observation["marker"] != marker or not observation["zap_version"]
            or type(observation["messages"]) is not int or observation["messages"] < 1):
        raise ValueError("Invalid scanner observation")
    if observation["active_scan_complete"] is not True:
        errors.append("Active scan did not complete")
    if type(observation["passive_remaining"]) is not int or observation["passive_remaining"] != 0:
        errors.append("Passive scan is incomplete")
    if not isinstance(observation["missing_urls"], list) or observation["missing_urls"]:
        errors.append("Required URLs were not reached by ZAP with HTTP 200")
    if not isinstance(observation["server_errors"], list) or observation["server_errors"]:
        errors.append("Target returned 5xx during ZAP requests")
    if type(exit_code) is not int or exit_code not in {0, 1, 2}:
        errors.append("ZAP execution failed or was interrupted")
    if not isinstance(report.get("@version"), str) or not report["@version"]:
        raise ValueError("ZAP JSON version is missing")
    sites = report["site"]
    if not isinstance(sites, list) or not sites:
        raise ValueError("ZAP JSON contains no scanned site")
    for site in sites:
        if site["@name"].rstrip("/") != target:
            raise ValueError("ZAP JSON belongs to a different target")
        alerts = site["alerts"]
        if not isinstance(alerts, list):
            raise ValueError("ZAP alerts must be a list")
        for alert in alerts:
            plugin = str(alert["pluginid"])
            risk = str(alert["riskcode"])
            if not plugin.isdigit() or risk not in {"0", "1", "2", "3"}:
                raise ValueError("Invalid plugin or risk code in ZAP alert")
            instances = alert["instances"]
            if not isinstance(instances, list) or not instances:
                raise ValueError("ZAP alert has no instances")
            item = {"plugin_id": plugin, "risk_code": int(risk),
                    "name": str(alert.get("name", alert.get("alert", plugin))),
                    "instances": len(instances)}
            # High is blocking even when an unknown/new plugin is WARN or IGNORE in TSV.
            if risk == "3" or rules.get(plugin) == "FAIL":
                findings.append(item)
            else:
                warnings.append(item)
    if exit_code == 1 and not findings:
        errors.append("ZAP returned FAIL without an explained blocking finding")
    decision = "scan_error" if errors else "blocked" if findings else "passed"
    return {"schema": 1, "target": target, "decision": decision,
            "blocking_findings": findings, "nonblocking_findings": warnings,
            "scan_errors": errors, "zap_exit_code": exit_code,
            "policy": "All High risks and explicit TSV FAIL rules block delivery"}


def evaluate_files(directory, rules_file):
    directory = Path(directory)
    try:
        def load(name):
            return json.loads((directory / name).read_text(encoding="utf-8"))
        return analyze(load("zap.json"), load("state.json"), load("before.json"),
                       load("after.json"), load("observation.json"),
                       int((directory / "exit-code.txt").read_text(encoding="utf-8").strip()),
                       read_rules(rules_file))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return {"schema": 1, "decision": "scan_error", "blocking_findings": [],
                "nonblocking_findings": [],
                "scan_errors": ["Missing or invalid evidence: " + type(error).__name__]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("dast-reports"))
    parser.add_argument("--rules", type=Path, default=Path(".zap/rules.tsv"))
    parser.add_argument("--output", type=Path, default=Path("dast-reports/gate.json"))
    args = parser.parse_args(argv)
    result = evaluate_files(args.directory, args.rules)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["decision"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
