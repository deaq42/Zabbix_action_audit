"""Connection settings: CLI arguments > environment > secrets file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_KEYS = {
    "url": re.compile(r"^\s*zabbix[_ ]?url\s*[:=]\s*(.+?)\s*$", re.I),
    "token": re.compile(r"^\s*zabbix[_ ]?(?:api[_ ]?)?token\s*[:=]\s*(.+?)\s*$", re.I),
}


@dataclass
class Settings:
    url: str
    token: str


def read_secrets(path: str | Path) -> dict[str, str]:
    """Parses lines like ``Zabbix_url: http://...`` and ``Zabbix token: ...``."""
    out: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        for key, rx in _KEYS.items():
            m = rx.match(line)
            if m:
                out[key] = m.group(1)
    return out


def resolve(url: str | None, token: str | None, secrets: str | Path | None) -> Settings:
    file_values = read_secrets(secrets) if secrets else {}
    url = url or os.environ.get("ZABBIX_URL") or file_values.get("url")
    token = token or os.environ.get("ZABBIX_TOKEN") or file_values.get("token")
    if not url or not token:
        raise ValueError("Не заданы URL и/или токен Zabbix (аргументы --url/--token, переменные ZABBIX_URL/ZABBIX_TOKEN "
                         "или файл secrets.txt)")
    return Settings(url, token)
