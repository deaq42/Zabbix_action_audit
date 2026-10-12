"""Connection settings: CLI arguments > environment > secrets file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_KEYS = {
    "url": re.compile(r"^\s*zabbix[_ ]?url\s*[:=]\s*(.+?)\s*$", re.I),
    "token": re.compile(r"^\s*zabbix[_ ]?(?:api[_ ]?)?token\s*[:=]\s*(.+?)\s*$", re.I),
    "verify_ssl": re.compile(r"^\s*zabbix[_ ]?verify[_ ]?ssl\s*[:=]\s*(.+?)\s*$", re.I),
}

_FALSE = {"0", "false", "no", "off", "нет"}
_TRUE = {"1", "true", "yes", "on", "да"}


@dataclass
class Settings:
    url: str
    token: str
    verify: bool | str = True  # False = no TLS verification, str = path to a CA bundle


def parse_verify(value: str) -> bool | str:
    """``false``/``no``/``0`` -> False, ``true``/``yes``/``1`` -> True, anything else is a CA bundle path."""
    v = value.strip()
    if v.lower() in _FALSE:
        return False
    if v.lower() in _TRUE:
        return True
    if not Path(v).is_file():
        raise ValueError(f"Проверка SSL: «{v}» — не true/false и не путь к файлу CA")
    return v


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


def resolve(url: str | None, token: str | None, secrets: str | Path | None, *,
            verify: bool | str | None = None) -> Settings:
    """``verify`` from the CLI wins over ZABBIX_VERIFY_SSL, which wins over ``Zabbix verify ssl:`` in the file."""
    file_values = read_secrets(secrets) if secrets else {}
    url = url or os.environ.get("ZABBIX_URL") or file_values.get("url")
    token = token or os.environ.get("ZABBIX_TOKEN") or file_values.get("token")
    if not url or not token:
        raise ValueError("Не заданы URL и/или токен Zabbix (аргументы --url/--token, переменные ZABBIX_URL/ZABBIX_TOKEN "
                         "или файл secrets.txt)")
    if verify is None:
        raw = os.environ.get("ZABBIX_VERIFY_SSL") or file_values.get("verify_ssl")
        verify = parse_verify(raw) if raw else True
    return Settings(url, token, verify)
