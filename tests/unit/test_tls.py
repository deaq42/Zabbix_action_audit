"""TLS verification: on (system CAs), off, and a custom CA bundle — against a real local HTTPS server."""

import json
import logging
import shutil
import ssl
import subprocess
import threading
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests

from zabbix_action_audit.api import ZabbixAPI
from zabbix_action_audit.cli import build_parser
from zabbix_action_audit.config import parse_verify, resolve


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server API
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps({"jsonrpc": "2.0", "result": "7.4.9", "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def https_server(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not found")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{server.server_port}/", str(cert)
    server.shutdown()


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")


def test_self_signed_rejected_by_default(https_server):
    url, _ = https_server
    with pytest.raises(requests.exceptions.SSLError):
        ZabbixAPI(url).version


def test_verification_off_warns_once(https_server, caplog):
    url, _ = https_server
    with caplog.at_level(logging.WARNING), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        api = ZabbixAPI(url, verify=False)
        assert api.version == (7, 4, 9)
        api._request("apiinfo.version", {}, auth=False)
    assert not [w for w in caught if "Unverified HTTPS" in str(w.message)]
    assert [r.message for r in caplog.records].count(f"Проверка TLS-сертификата {api.url} отключена") == 1


def test_custom_ca_bundle(https_server):
    url, cert = https_server
    assert ZabbixAPI(url, verify=cert).version == (7, 4, 9)


@pytest.mark.parametrize("value,expected", [("false", False), ("No", False), ("0", False), ("нет", False),
                                            ("true", True), ("yes", True), ("1", True)])
def test_parse_verify(value, expected):
    assert parse_verify(value) is expected


def test_parse_verify_path_and_error(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    assert parse_verify(f" {ca} ") == str(ca)
    with pytest.raises(ValueError):
        parse_verify("maybe")


def test_verify_priority(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets.txt"
    secrets.write_text("Zabbix_url: https://z/\nZabbix token: t\nZabbix verify ssl: false\n")
    monkeypatch.delenv("ZABBIX_VERIFY_SSL", raising=False)
    assert resolve(None, None, secrets).verify is False  # from the file
    monkeypatch.setenv("ZABBIX_VERIFY_SSL", "true")
    assert resolve(None, None, secrets).verify is True  # env beats the file
    assert resolve(None, None, secrets, verify=False).verify is False  # CLI beats env
    monkeypatch.delenv("ZABBIX_VERIFY_SSL")
    secrets.write_text("Zabbix_url: https://z/\nZabbix token: t\n")
    assert resolve(None, None, secrets).verify is True  # default


def test_cli_flags(tmp_path):
    p = build_parser()
    assert p.parse_args([]).verify is None
    assert p.parse_args(["--no-verify-ssl"]).verify is False
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    assert p.parse_args(["--ca-bundle", str(ca)]).verify == str(ca)
    with pytest.raises(SystemExit):
        p.parse_args(["--ca-bundle", str(tmp_path / "missing.pem")])
    with pytest.raises(SystemExit):
        p.parse_args(["--no-verify-ssl", "--ca-bundle", str(ca)])
