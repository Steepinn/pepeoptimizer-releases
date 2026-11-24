"""Учёт активаций в приватном GitHub-репозитории: activations/<хеш ключа>.json.

Создание файла без sha атомарно — второй ПК с тем же ключом получит отказ.
Время активации и «сейчас» берутся с серверов GitHub, а не с часов ПК.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any


_API = "https://api.github.com"
_TIMEOUT = 15


class StoreError(Exception):
    """Сервер недоступен или настроен неверно."""


class KeyTaken(Exception):
    """Ключ уже активирован на другом ПК."""


@dataclass
class Record:
    hwid: str
    plan: str
    activated_at: float
    server_now: float
    revoked: bool = False


def _config() -> tuple[str, str]:
    repo = os.environ.get("LICENSE_REPOSITORY", "")
    token = os.environ.get("LICENSE_STORE_TOKEN", "")
    return repo.strip(), token.strip()


def configured() -> bool:
    repo, token = _config()
    return bool(repo and token)


def _iso(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def _request(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any, float]:
    repo, token = _config()
    if not (repo and token):
        raise StoreError("Сервер активации не настроен")
    req = urllib.request.Request(
        f"{_API}/repos/{repo}" + (f"/{path}" if path else ""),
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PepeOptimazer",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            status, raw, date = resp.status, resp.read(), resp.headers.get("Date")
    except urllib.error.HTTPError as exc:
        status, raw, date = exc.code, exc.read(), exc.headers.get("Date") if exc.headers else None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise StoreError(f"Нет связи с сервером активации ({exc})") from exc
    try:
        data = json.loads(raw or b"null")
    except json.JSONDecodeError:
        data = None
    now = parsedate_to_datetime(date).timestamp() if date else 0.0
    if status in (401, 403):
        raise StoreError("Сервер активации отклонил доступ (проверьте токен)")
    return status, data, now


def _path(key_hash: str) -> str:
    return f"contents/activations/{key_hash}.json"


def _encode(payload: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(payload, ensure_ascii=False, indent=1).encode()).decode()


def fetch(key_hash: str) -> Record | None:
    """Запись активации или None, если ключ свободен."""
    status, data, now = _request("GET", _path(key_hash))
    if status == 404:
        _ensure_repo()
        return None
    if status != 200 or not isinstance(data, dict):
        raise StoreError(f"Сервер активации ответил {status}")
    try:
        info = json.loads(base64.b64decode(data.get("content") or ""))
    except (ValueError, json.JSONDecodeError) as exc:
        raise StoreError("Повреждённая запись активации") from exc
    activated = info.get("activated_at")
    if not activated:
        activated = _first_commit_time(key_hash) or now
    return Record(
        hwid=str(info.get("hwid") or ""),
        plan=str(info.get("plan") or ""),
        activated_at=float(activated),
        server_now=now,
        revoked=bool(info.get("revoked")),
    )


def _ensure_repo() -> None:
    """404 на файл значит «ключ свободен», только если сам репозиторий виден токену."""
    status, _data, _now = _request("GET", "")
    if status != 200:
        raise StoreError("Репозиторий активаций недоступен (проверьте REPO и доступ токена)")


def _first_commit_time(key_hash: str) -> float | None:
    status, data, _ = _request("GET", f"commits?path=activations/{key_hash}.json&per_page=100")
    if status != 200 or not isinstance(data, list) or not data:
        return None
    return _iso(data[-1]["commit"]["committer"]["date"])


def claim(key_hash: str, hwid: str, plan: str, app_version: str) -> Record:
    """Занимает ключ за этим ПК. Повторно на том же ПК — вернёт прежнюю запись."""
    payload = {"hwid": hwid, "plan": plan, "app": app_version}
    status, data, now = _request("PUT", _path(key_hash), {"message": f"activate {plan}", "content": _encode(payload)})
    if status in (409, 422):
        record = fetch(key_hash)
        if record is None:
            raise StoreError("Не удалось занять ключ, попробуйте ещё раз")
        if record.revoked:
            raise KeyTaken("Ключ заблокирован")
        if record.hwid != hwid:
            raise KeyTaken("Ключ уже активирован на другом устройстве")
        return record
    if status == 404:
        _ensure_repo()
    if status != 201 or not isinstance(data, dict):
        raise StoreError(f"Сервер активации ответил {status}")

    activated = _iso(data["commit"]["committer"]["date"])
    sha = data.get("content", {}).get("sha")
    if sha:
        payload["activated_at"] = activated
        _request("PUT", _path(key_hash), {"message": "activation time", "content": _encode(payload), "sha": sha})
    return Record(hwid=hwid, plan=plan, activated_at=activated, server_now=now or activated)
