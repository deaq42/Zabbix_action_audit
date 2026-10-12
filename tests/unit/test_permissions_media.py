import pytest

from builders import RawBuilder
from zabbix_action_audit import constants as C
from zabbix_action_audit import media as M
from zabbix_action_audit import permissions as P
from zabbix_action_audit.conditions import MODE_POTENTIAL, build_candidates
from zabbix_action_audit.model import Snapshot

R, RW, D = C.PERM_READ, C.PERM_READ_WRITE, C.PERM_DENY


@pytest.fixture
def env():
    b = RawBuilder()
    g1, g2, g3 = b.group("A"), b.group("B"), b.group("C")
    h12 = b.host("h12", [g1, g2], tags=[("env", "prod")])
    h3 = b.host("h3", [g3])
    t12 = b.trigger([h12], "t12", tags=[("svc", "db")])
    t3 = b.trigger([h3], "t3")
    t_multi = b.trigger([h12, h3], "multi")
    return b, dict(g1=g1, g2=g2, g3=g3, h12=h12, h3=h3, t12=t12, t3=t3, t_multi=t_multi)


def access(b, uid, triggerid):
    snap = Snapshot(b.build())
    cand = next(c for c in build_candidates(snap, MODE_POTENTIAL) if c.key == triggerid)
    return P.PermissionResolver(snap).access(uid, cand).code


def test_super_admin_and_disabled(env):
    b, i = env
    ug_off = b.usergroup("off", {i["g1"]: R}, enabled=False)
    su = b.user("su", [b.usergroup("admins")], super_admin=True)
    off = b.user("off", [ug_off])
    assert access(b, su, i["t3"]) == P.ACCESS_OK
    assert access(b, off, i["t12"]) == P.USER_DISABLED


def test_deny_wins_between_user_groups(env):
    b, i = env
    u = b.user("u", [b.usergroup("rw", {i["g1"]: RW}), b.usergroup("deny", {i["g1"]: D})])
    assert access(b, u, i["t12"]) == P.USER_NO_HOST_ACCESS


def test_deny_on_any_host_group_wins(env):
    b, i = env
    u = b.user("u", [b.usergroup("ug", {i["g1"]: R, i["g2"]: D})])
    assert access(b, u, i["t12"]) == P.USER_NO_HOST_ACCESS


def test_one_readable_group_is_enough(env):
    b, i = env
    u = b.user("u", [b.usergroup("ug", {i["g2"]: R})])
    assert access(b, u, i["t12"]) == P.ACCESS_OK
    assert access(b, u, i["t3"]) == P.USER_NO_HOST_ACCESS


def test_multi_host_trigger_needs_all_hosts(env):
    b, i = env
    u = b.user("u", [b.usergroup("ug", {i["g1"]: R})])
    assert access(b, u, i["t_multi"]) == P.USER_NO_HOST_ACCESS


def test_tag_filters(env):
    b, i = env
    match = b.user("m", [b.usergroup("m", {i["g1"]: R}, tag_filters=[(i["g1"], "svc", "db")])])
    any_val = b.user("a", [b.usergroup("a", {i["g1"]: R}, tag_filters=[(i["g1"], "env", "")])])
    miss = b.user("x", [b.usergroup("x", {i["g1"]: R}, tag_filters=[(i["g1"], "svc", "web")])])
    both = b.user("b", [b.usergroup("x2", {i["g1"]: R}, tag_filters=[(i["g1"], "svc", "web")]),
                        b.usergroup("full", {i["g1"]: R})])
    assert access(b, match, i["t12"]) == P.ACCESS_OK
    assert access(b, any_val, i["t12"]) == P.ACCESS_OK
    assert access(b, miss, i["t12"]) == P.USER_TAG_FILTER_BLOCKS
    assert access(b, both, i["t12"]) == P.ACCESS_OK


def check_media(b, uid, mediatypeid="0", severity=3, **kw):
    snap = Snapshot(b.build())
    return M.MediaChecker(snap).check(snap.users[uid], mediatypeid, severity, **kw)


def codes(res):
    return {i.code for i in res.issues}


def test_media_checks():
    b = RawBuilder()
    ug = b.usergroup("ug")
    mail, sms = b.mediatype("Mail"), b.mediatype("SMS", enabled=False)
    tg = b.mediatype("TG", templates=(0,))
    none = b.user("none", [ug])
    off = b.user("off", [ug], medias=[b.media(mail, active=False)])
    sev = b.user("sev", [ug], medias=[b.media(mail, severity=0b110000)])
    on_sms = b.user("sms", [ug], medias=[b.media(sms)])
    mixed = b.user("mixed", [ug], medias=[b.media(sms), b.media(mail, period="1-5,09:00-18:00")])
    tgu = b.user("tg", [ug], medias=[b.media(tg, sendto="")])

    assert codes(check_media(b, none)) == {M.USER_NO_MEDIA}
    assert codes(check_media(b, mixed, mail)) == {M.MEDIA_PERIOD_LIMITED}
    assert codes(check_media(b, mixed, tg)) == {M.USER_NO_MEDIA}
    assert codes(check_media(b, off)) == {M.MEDIA_DISABLED}
    assert codes(check_media(b, sev, severity=3)) == {M.MEDIA_SEVERITY_EXCLUDED}
    assert check_media(b, sev, severity=5).ok
    assert codes(check_media(b, on_sms)) == {M.MEDIATYPE_DISABLED}
    res = check_media(b, mixed)  # all media types: SMS is broken, mail works
    assert res.ok and codes(res) == {M.MEDIA_PERIOD_LIMITED}
    res = check_media(b, tgu, opkind=C.OPKIND_RECOVERY)
    assert res.ok and codes(res) == {M.MEDIA_EMPTY_SENDTO, M.MEDIATYPE_NO_MESSAGE_TEMPLATE}
    assert codes(check_media(b, tgu, opkind=C.OPKIND_RECOVERY, default_msg=False)) == {M.MEDIA_EMPTY_SENDTO}
    # 1_700_000_000 = Tuesday 22:13 UTC -> outside 09-18 (local tz may differ, so use utc)
    from datetime import timezone
    snap = Snapshot(b.build())
    res = M.MediaChecker(snap, timezone.utc).check(snap.users[mixed], mail, 3, clock=1_700_000_000)
    assert codes(res) == {M.MEDIA_PERIOD_EXCLUDED}
