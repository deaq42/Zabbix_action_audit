import json

from builders import RawBuilder
from zabbix_action_audit import constants as C
from zabbix_action_audit.api import ZabbixAPI, api_endpoint, parse_version
from zabbix_action_audit.auditor import Auditor
from zabbix_action_audit.cli import main
from zabbix_action_audit.config import read_secrets, resolve
from zabbix_action_audit.model import Snapshot
from zabbix_action_audit.report import render_html, render_json, render_text


def scenario():
    b = RawBuilder()
    g = b.group("Prod")
    h = b.host("srv", [g])
    t_hi = b.trigger([h], "Disk full", priority=5)
    t_lo = b.trigger([h], "Info msg", priority=1)
    mail = b.mediatype("Mail")
    ug_ok = b.usergroup("ops", {g: C.PERM_READ})
    ug_none = b.usergroup("nobody")
    ok = b.user("ok", [ug_ok], medias=[b.media(mail)])
    hi_only = b.user("hi", [ug_ok], medias=[b.media(mail, severity=0b110000)])
    blind = b.user("blind", [ug_none], medias=[b.media(mail)])
    empty = b.usergroup("empty")
    b.action("Main", [(C.COND_HOST_GROUP, C.OP_EQUAL, g)],
             operations=[b.send(users=[blind], groups=[ug_ok, empty], mediatypeid=mail)])
    b.action("Nothing", [(C.COND_SEVERITY, C.OP_EQUAL, 0)], operations=[b.send(users=[ok])])
    b.action("Nobody", [], operations=[b.send()])
    b.action("Off", [], enabled=False, operations=[b.send(users=[blind])])
    b.problem(t_hi, "Disk full", severity=5)
    return b, dict(t_hi=t_hi, t_lo=t_lo, ok=ok, hi_only=hi_only, blind=blind)


def run(b, **kw):
    return Auditor(Snapshot(b.build())).run(["potential", "active"], **kw)


def test_main_action_outcomes():
    b, i = scenario()
    res = run(b, uncovered=True)
    main_ = next(a for a in res.actions if a.name == "Main")
    pot = main_.modes["potential"]
    assert sorted(pot.matched) == sorted([i["t_hi"], i["t_lo"]])
    op = pot.operations[0]
    assert [f.code for f in op.findings] == ["OP_USERGROUP_EMPTY"]
    by_user = {r.userid: r for r in op.recipients}
    assert by_user[i["blind"]].via == ["напрямую"]
    assert by_user[i["ok"]].via == ["группа «ops»"]

    assert by_user[i["ok"]].counts["OK"] == 2
    hi = by_user[i["hi_only"]]
    assert hi.counts == {"OK": 1, "INFO": 0, "WARN": 0, "FAIL": 1}
    assert {g.codes[0] for g in hi.outcomes if g.codes} == {"MEDIA_SEVERITY_EXCLUDED"}
    assert [f.code for f in hi.findings] == ["COND_SEVERITY_PARTIAL"]
    blind = by_user[i["blind"]]
    assert blind.outcomes[0].codes == ["USER_NO_HOST_ACCESS"] and blind.counts["FAIL"] == 2
    assert [f.code for f in blind.findings] == ["COND_HOST_NOT_ACCESSIBLE"]

    act = main_.modes["active"]
    assert len(act.matched) == 1 and act.counts["FAIL"] == 1  # the blind user


def test_action_level_findings_and_counts():
    b, i = scenario()
    res = run(b, uncovered=True)
    by_name = {a.name: a for a in res.actions}
    assert [f.code for f in by_name["Nothing"].modes["potential"].findings] == ["ACTION_MATCHES_NOTHING"]
    assert [f.code for f in by_name["Nobody"].modes["potential"].operations[0].findings] == ["OP_NO_RECIPIENTS"]
    assert by_name["Off"].findings[0].code == "ACTION_DISABLED"
    assert res.actions[-1].name == "Off"  # disabled actions go last
    # FAIL of the disabled action (blind user: 2 triggers + 1 problem) do not count
    assert res.count("FAIL") == res.count("FAIL", enabled_only=False) - 3
    assert res.uncovered == {"potential": [], "active": []}


def test_only_undecided_matches_are_reported():
    b = RawBuilder()
    h = b.host("h", [b.group("G")])
    b.trigger([h], "Value is {ITEM.LASTVALUE}")
    b.action("A", [(C.COND_EVENT_NAME, C.OP_LIKE, "zzz")], operations=[b.send()])
    pot = run(b).actions[0].modes["potential"]
    assert not pot.matched and len(pot.undecided) == 1
    assert [f.code for f in pot.findings] == ["ACTION_ONLY_UNDECIDED"]


def test_skip_disabled_and_filter():
    b, _ = scenario()
    assert "Off" not in {a.name for a in run(b, skip_disabled=True).actions}
    assert [a.name for a in run(b, action_filter=["main"]).actions] == ["Main"]


def test_renderers():
    b, _ = scenario()
    res = run(b, uncovered=True)
    assert "USER_NO_HOST_ACCESS" in render_text(res)
    data = json.loads(render_json(res))
    assert data["summary"]["FAIL"] == res.count("FAIL")
    html = render_html(res)
    assert "<html" in html and "Disk full" in html and "</script>" in html


def test_cli_from_snapshot(tmp_path, capsys):
    b, _ = scenario()
    snap = tmp_path / "s.json"
    snap.write_text(json.dumps(b.build()))
    out = tmp_path / "r.html"
    assert main(["--from-snapshot", str(snap), "-o", str(out)]) == 1
    assert out.read_text().startswith("<!doctype html>")
    assert main(["--from-snapshot", str(snap), "--action", "Nothing", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["actions"][0]["name"] == "Nothing"
    assert main(["--from-snapshot", str(snap), "--action", "missing"]) == 2


def test_secrets_parsing(tmp_path, monkeypatch):
    p = tmp_path / "secrets.txt"
    p.write_text("Zabbix_url: http://z/\nZabbix token: abc123\n")
    assert read_secrets(p) == {"url": "http://z/", "token": "abc123"}
    monkeypatch.setenv("ZABBIX_TOKEN", "env")
    s = resolve(None, None, p)
    assert (s.url, s.token) == ("http://z/", "env")
    assert resolve("http://cli", "cli", p).token == "cli"


def test_api_auth_style_depends_on_version(monkeypatch):
    sent = []

    class Resp:
        status_code, reason, content = 200, "OK", b""

        def __init__(self, result):
            self.result = result

        def raise_for_status(self):
            pass

        def json(self):
            return {"jsonrpc": "2.0", "result": self.result, "id": 1}

    for version, bearer in (("6.0.30", False), ("6.4.0", True), ("7.4.9", True)):
        api = ZabbixAPI("http://z", "tok")

        def post(url, json, headers, timeout, version=version):
            sent.append((json, headers))
            return Resp(version if json["method"] == "apiinfo.version" else [])

        monkeypatch.setattr(api.session, "post", post)
        api.call("host.get", {})
        version_call, call = sent[-2], sent[-1]
        assert "auth" not in version_call[0] and not version_call[1]
        assert ("Authorization" in call[1]) is bearer
        assert ("auth" in call[0]) is (not bearer)
    assert api_endpoint("http://z/") == "http://z/api_jsonrpc.php"
    assert parse_version("7.0.0rc1") == (7, 0, 0)
