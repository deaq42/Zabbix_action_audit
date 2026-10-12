"""Thin Zabbix JSON-RPC client that works with 6.0 LTS and 7.x.

Differences handled here:
- 6.4+ accepts ``Authorization: Bearer``; 7.2+ rejects the ``auth`` body field.
  Older versions (6.0, 6.2) only understand the ``auth`` field.
- ``apiinfo.version`` must be called without any authorization.
"""

from __future__ import annotations

import itertools
import logging
import re
import time
from typing import Any

import requests
import urllib3

log = logging.getLogger(__name__)


class ZabbixAPIError(Exception):
    def __init__(self, method: str, code: int, message: str, data: str = ""):
        self.method, self.code, self.message, self.data = method, code, message, data
        super().__init__(f"{method}: {message} {data}".strip())


class ZabbixTransportError(Exception):
    """The frontend failed to answer (HTTP 5xx, timeout, truncated body) — usually PHP memory_limit or
    max_execution_time on a request that returns too much data."""

    def __init__(self, method: str, reason: str):
        self.method, self.reason = method, reason
        super().__init__(f"{method}: {reason}")


def parse_version(text: str) -> tuple[int, int, int]:
    parts = [int(m.group()) if (m := re.match(r"\d+", p)) else 0 for p in text.split(".")[:3]]
    return tuple(parts + [0] * (3 - len(parts)))  # type: ignore[return-value]


def api_endpoint(url: str) -> str:
    url = url.strip()
    if url.endswith("api_jsonrpc.php"):
        return url
    return url.rstrip("/") + "/api_jsonrpc.php"


def frontend_base(url: str) -> str:
    url = api_endpoint(url)
    return url[: -len("api_jsonrpc.php")]


class ZabbixAPI:
    def __init__(self, url: str, token: str | None = None, *, verify: bool | str = True, timeout: float = 120):
        """``verify``: True — system CAs, False — no TLS verification, str — path to a CA bundle."""
        self.url = api_endpoint(url)
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        if verify is False and self.url.startswith("https://"):
            # one explicit warning instead of an InsecureRequestWarning on every request
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning("Проверка TLS-сертификата %s отключена", self.url)
        self.session.headers["Content-Type"] = "application/json-rpc"
        self._ids = itertools.count(1)
        self._version: tuple[int, int, int] | None = None
        self.version_str = ""

    # -- version ---------------------------------------------------------
    @property
    def version(self) -> tuple[int, int, int]:
        if self._version is None:
            self.version_str = self._request("apiinfo.version", {}, auth=False)
            self._version = parse_version(self.version_str)
        return self._version

    def at_least(self, major: int, minor: int = 0) -> bool:
        return self.version[:2] >= (major, minor)

    # -- calls -----------------------------------------------------------
    def call(self, method: str, params: Any = None) -> Any:
        return self._request(method, {} if params is None else params, auth=True)

    def login(self, username: str, password: str) -> str:
        self.token = self._request("user.login", {"username": username, "password": password}, auth=False)
        return self.token  # type: ignore[return-value]

    def _request(self, method: str, params: Any, *, auth: bool) -> Any:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params, "id": next(self._ids)}
        headers = {}
        if auth and self.token:
            if self.at_least(6, 4):
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                payload["auth"] = self.token
        log.debug("-> %s %s", method, _describe(params))
        started = time.monotonic()
        try:
            resp = self.session.post(self.url, json=payload, headers=headers, timeout=self.timeout)
        except requests.Timeout as e:
            raise ZabbixTransportError(method, f"нет ответа за {self.timeout:g} с") from e
        if resp.status_code >= 500:
            raise ZabbixTransportError(method, f"HTTP {resp.status_code} {resp.reason}")
        resp.raise_for_status()
        try:
            body = resp.json()
        except ValueError as e:
            raise ZabbixTransportError(method, "ответ не является JSON (обрезан или ошибка PHP)") from e
        log.debug("<- %s %.1fs %d KB", method, time.monotonic() - started, len(resp.content) // 1024)
        if "error" in body:
            err = body["error"]
            raise ZabbixAPIError(method, err.get("code", 0), err.get("message", ""), err.get("data", ""))
        return body["result"]


def _describe(params: Any) -> str:
    """Short description of request parameters for debug logs (sizes of id lists instead of the ids)."""
    if not isinstance(params, dict):
        return ""
    return " ".join(f"{k}=[{len(v)}]" for k, v in params.items() if isinstance(v, list) and k.endswith("ids"))
