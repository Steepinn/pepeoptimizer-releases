"""GitHub Actions handler. Credentials are read only from Actions Secrets."""
from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

import activation_protocol as protocol
import activation_store as store
from key_hashes import LIFETIME, TRIAL


def api(method, path, payload=None):
    request = urllib.request.Request("https://api.github.com" + path, method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                 "Accept": "application/vnd.github+json", "User-Agent": "PepeOptimazer-Activation",
                 "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None
        raise RuntimeError(f"GitHub operation failed: HTTP {exc.code}") from None


def status_record(key_hash, record):
    return {"key_hash": key_hash, "binding": protocol.binding(key_hash, record.hwid),
            "plan": record.plan, "activated_at": record.activated_at,
            "revoked": bool(record.revoked), "updated_at": time.time()}


def publish_status(key_hash, record):
    signed = protocol.sign_status(status_record(key_hash, record), os.environ["LICENSE_SIGNING_KEY"])
    repo = os.environ["GITHUB_REPOSITORY"]
    path = f"/repos/{repo}/contents/license-status/{key_hash}.json"
    code, old = api("GET", path)
    if code == 200:
        previous = json.loads(base64.b64decode(old["content"]))["record"]
        comparable = lambda value: {k: v for k, v in value.items() if k != "updated_at"}
        if comparable(previous) == comparable(signed["record"]):
            return
    data = {"message": "Update signed license status", "content": protocol.b64(protocol.canonical(signed))}
    if code == 200:
        data["sha"] = old["sha"]
    api("PUT", path, data)


def activate(payload):
    key = payload.get("key", "")
    hwid = payload.get("hwid", "")
    if not isinstance(key, str) or not re.fullmatch(r"[A-HJ-NP-Z2-9]{16}", key):
        return {"error": "invalid_key"}
    if not isinstance(hwid, str) or not re.fullmatch(r"[a-f0-9]{32}", hwid):
        return {"error": "invalid_request"}
    key_hash = hashlib.sha256(f"pepe+7f3c1e9a5b2d4086:{key}".encode()).hexdigest()
    plan = "lifetime" if key_hash in LIFETIME else "trial" if key_hash in TRIAL else None
    if plan is None:
        return {"error": "invalid_key"}
    try:
        record = store.claim(key_hash, hwid, plan, str(payload.get("app", ""))[:32])
        if record.plan != plan:
            return {"error": "store_unavailable"}
        publish_status(key_hash, record)
        return {"record": asdict(record)}
    except store.KeyTaken:
        return {"error": "key_taken"}
    except store.StoreError:
        return {"error": "store_unavailable"}


def handle_issue(event):
    issue = event["issue"]
    if not str(issue.get("title", "")).startswith("Pepe+ activation "):
        return
    repo = os.environ["GITHUB_REPOSITORY"]
    number = int(issue["number"])
    try:
        payload, secret = protocol.decrypt_request(issue.get("body", ""), os.environ["LICENSE_DECRYPT_KEY"])
        if not re.fullmatch(r"[a-f0-9]{32}", str(payload.get("nonce", ""))):
            raise ValueError("Invalid request nonce")
    except Exception:
        api("PATCH", f"/repos/{repo}/issues/{number}", {"state": "closed"})
        return
    result = activate(payload)
    result["nonce"] = payload["nonce"]
    api("POST", f"/repos/{repo}/issues/{number}/comments",
        {"body": protocol.encrypt_reply(result, secret)})
    api("PATCH", f"/repos/{repo}/issues/{number}", {"state": "closed"})


def sync_statuses():
    code, files, _ = store._request("GET", "contents/activations")
    if code != 200 or not isinstance(files, list):
        raise RuntimeError("License storage is unavailable")
    count = 0
    for item in files:
        name = item.get("name", "")
        if not re.fullmatch(r"[a-f0-9]{64}\.json", name):
            continue
        key_hash = name[:-5]
        record = store.fetch(key_hash)
        if record is not None:
            publish_status(key_hash, record)
            count += 1
    # Removed activations become signed revocations; existing local caches are preserved on network errors.
    repo = os.environ["GITHUB_REPOSITORY"]
    _, published = api("GET", f"/repos/{repo}/contents/license-status")
    existing = {item["name"] for item in files}
    if isinstance(published, list):
        for item in published:
            if re.fullmatch(r"[a-f0-9]{64}\.json", item.get("name", "")) and item["name"] not in existing:
                _, content = api("GET", f"/repos/{repo}/contents/{item['path']}")
                previous = json.loads(base64.b64decode(content["content"]))["record"]
                if not previous.get("revoked"):
                    signed = protocol.sign_status({**previous, "revoked": True, "updated_at": time.time()},
                                                  os.environ["LICENSE_SIGNING_KEY"])
                    api("PUT", f"/repos/{repo}/contents/{item['path']}", {
                        "message": "Revoke removed license", "sha": content["sha"],
                        "content": protocol.b64(protocol.canonical(signed))})
    print(f"Signed license statuses synchronized: {count}")


if __name__ == "__main__":
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if os.environ["GITHUB_EVENT_NAME"] == "issues":
        handle_issue(event)
    else:
        sync_statuses()
