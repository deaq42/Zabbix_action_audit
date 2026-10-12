"""Live stands for integration tests.

- ``local``  — Zabbix from secrets.txt (192.168.88.40, 7.4)
- ``zbx60``  — disposable 6.0 LTS from tests/zabbix60/docker-compose.yml (Admin / zabbix)

Select with ZAA_STANDS=local,zbx60 (default: every reachable stand).
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests

from zabbix_action_audit.api import ZabbixAPI
from zabbix_action_audit.config import parse_verify, read_secrets

from .scenario import Scenario, leftover_cleanup

ROOT = Path(__file__).resolve().parents[2]


def _stands() -> dict[str, dict]:
    stands = {}
    secrets = read_secrets(ROOT / "secrets.txt")
    if secrets.get("url") and secrets.get("token"):
        stands["local"] = {"url": secrets["url"], "token": secrets["token"],
                           "verify": parse_verify(secrets.get("verify_ssl", "true"))}
    stands["zbx60"] = {"url": os.environ.get("ZAA_ZBX60_URL", "http://127.0.0.1:8060/"), "login": ("Admin", "zabbix")}
    wanted = os.environ.get("ZAA_STANDS")
    if wanted:
        stands = {k: v for k, v in stands.items() if k in wanted.split(",")}
    # stands are on the local network: never send them through an HTTP proxy
    hosts = {urlparse(s["url"]).hostname for s in stands.values()}
    os.environ["NO_PROXY"] = ",".join(filter(None, [os.environ.get("NO_PROXY", ""), *hosts]))
    return stands


STANDS = _stands()


def connect(name: str) -> ZabbixAPI:
    cfg = STANDS[name]
    api = ZabbixAPI(cfg["url"], cfg.get("token"), verify=cfg.get("verify", True), timeout=30)
    try:
        api.version
    except requests.RequestException as e:
        pytest.skip(f"stand {name} unreachable: {e}")
    if "login" in cfg:
        api.login(*cfg["login"])
    return api


@pytest.fixture(scope="module", params=sorted(STANDS))
def stand(request) -> tuple[str, ZabbixAPI]:
    return request.param, connect(request.param)


@pytest.fixture(scope="module")
def scenario(stand):
    name, api = stand
    leftover_cleanup(api)
    sc = Scenario(api).build()
    sc.stand = name  # type: ignore[attr-defined]
    yield sc
    sc.cleanup()
