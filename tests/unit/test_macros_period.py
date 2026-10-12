from datetime import datetime

import pytest

from builders import RawBuilder
from zabbix_action_audit.macros import MacroResolver, tokenize
from zabbix_action_audit.model import Snapshot
from zabbix_action_audit.period import parse_period


def test_tokenize_balanced_braces():
    assert tokenize("a {{ITEM.VALUE}.regsub(\"x\",1)} b {$M:\"c\"} {") == [
        (False, "a "), (True, '{{ITEM.VALUE}.regsub("x",1)}'), (False, " b "), (True, '{$M:"c"}'), (False, " {")]


@pytest.fixture
def resolver():
    b = RawBuilder()
    g = b.group("G")
    t2 = b.template("T2")
    t1 = b.template("T1", parents=[t2])
    h = b.host("h", [g], templates=[t1])
    b.global_macro("{$G}", "global")
    b.global_macro("{$UTIL}", "80")
    b.global_macro('{$UTIL:"cache"}', "95")
    b.global_macro("{$SECRET}", None)
    b.host_macro(t2, "{$UTIL}", "70")
    b.host_macro(t2, '{$UTIL:regex:"^disk"}', "60")
    b.host_macro(t1, "{$ONLY_T1}", "t1")
    b.host_macro(h, "{$ONLY_T1}", "host")
    return MacroResolver(Snapshot(b.build())), h


def test_resolution_order(resolver):
    r, h = resolver
    assert r.user_macro("{$ONLY_T1}", h) == "host"
    assert r.user_macro("{$UTIL}", h) == "70"  # nested template beats global
    assert r.user_macro("{$G}", h) == "global"
    assert r.user_macro("{$UTIL}", None) == "80"


def test_context(resolver):
    r, h = resolver
    assert r.user_macro('{$UTIL:"cache"}', h) == "95"  # exact context anywhere beats plain macro
    assert r.user_macro('{$UTIL:"disk /"}', h) == "60"  # regex context
    assert r.user_macro('{$UTIL:"other"}', h) == "70"  # falls back to the macro without context


def test_secret_and_unknown_stay_unresolved(resolver):
    r, h = resolver
    e = r.expand("x {$SECRET} y {$NOPE} {ITEM.VALUE}", [h])
    assert not e.exact and e.text == "x «?» y «?» «?»"
    assert e.contains("y") is True and e.contains("zzz") is None
    assert r.expand("{HOST.HOST}/{HOST.NAME}/{HOSTNAME}", [h]).text == "h/H/h"
    assert not r.expand("{HOST.NAME}", [h, h]).exact  # multi-host order is unknown


def test_equals_with_holes(resolver):
    r, h = resolver
    e = r.expand("svc-{ITEM.VALUE}", [h])
    assert e.equals("svc-nginx") is None
    assert e.equals("db-nginx") is False


def test_period():
    p = parse_period("1-5,09:00-18:00;6,10:00-12:00")
    assert not p.always
    assert p.contains(datetime(2026, 10, 12, 9, 0))  # Monday
    assert not p.contains(datetime(2026, 10, 12, 18, 0))
    assert p.contains(datetime(2026, 10, 17, 11, 0))  # Saturday
    assert not p.contains(datetime(2026, 10, 18, 11, 0))  # Sunday
    assert parse_period("1-7,00:00-24:00").always
    assert parse_period("1-7,00:00-12:00;1-7,12:00-24:00").always
    assert parse_period("{$WORKTIME}") is None
    assert parse_period("8,00:00-24:00") is None
