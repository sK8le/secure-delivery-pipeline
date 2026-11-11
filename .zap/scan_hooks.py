"""Observe ZAP's own requests; persist no credentials, headers or response bodies."""
import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit

# Packaged scans omit __file__; the workflow runs in its writable report directory.
REPORTS = Path.cwd()


def zap_started(zap, target):
    state = json.loads((REPORTS / "state.json").read_text(encoding="utf-8"))
    if state["target"] != target.rstrip("/"):
        raise ValueError("ZAP target does not match the preflight")
    # Put authenticated, seeded endpoints into ZAP's site tree before active scanning.
    for item in state["required"]:
        body = zap.urlopen(state["target"] + item["path"])
        if item["contains"] and item["contains"] not in body:
            raise ValueError("ZAP did not reach the expected authenticated content")
    print("ZAP hooks: authenticated routes reached", flush=True)


def observe(zap, state):
    target = state["target"]
    required = {target + item["path"] for item in state["required"]}
    reached = set()
    errors = []
    count = 0
    for start in range(0, 100000, 500):
        messages = zap.core.messages(baseurl=target, start=start, count=500)
        if not isinstance(messages, list):
            raise ValueError("Invalid ZAP history response")
        for message in messages:
            method, uri, _ = message["requestHeader"].splitlines()[0].split(" ", 2)
            url = urljoin(target, uri)
            if urlsplit(url).netloc != urlsplit(target).netloc:
                continue
            code = int(message["responseHeader"].splitlines()[0].split(" ", 2)[1])
            count += 1
            if method == "GET" and url in required and code == 200:
                reached.add(url)
            if code >= 500:
                errors.append({"method": method, "path": urlsplit(url).path, "status": code})
        if len(messages) < 500:
            break
    else:
        raise ValueError("ZAP history exceeded the collection limit")
    scans = zap.ascan.scans
    complete = bool(scans) and all(int(scan["progress"]) == 100 for scan in scans)
    return {"schema": 1, "target": target, "marker": state["marker"],
            "zap_version": zap.core.version, "messages": count,
            "missing_urls": sorted(required - reached), "server_errors": errors,
            "active_scan_complete": complete,
            "passive_remaining": int(zap.pscan.records_to_scan)}


def zap_pre_shutdown(zap):
    state = json.loads((REPORTS / "state.json").read_text(encoding="utf-8"))
    result = observe(zap, state)
    (REPORTS / "observation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("ZAP hooks: scan observation saved", flush=True)
