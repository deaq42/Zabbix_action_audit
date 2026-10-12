"""End-to-end checks on live Zabbix stands (run with: pytest -m integration)."""

from __future__ import annotations

import pytest

from zabbix_action_audit import constants as C
from zabbix_action_audit.api import ZabbixAPI, ZabbixAPIError
from zabbix_action_audit.auditor import Auditor
from zabbix_action_audit.cli import main
from zabbix_action_audit.conditions import MODE_ACTIVE, MODE_POTENTIAL, build_candidates
from zabbix_action_audit.loader import fetch_raw
from zabbix_action_audit.model import Snapshot
from zabbix_action_audit.permissions import ACCESS_OK, PermissionResolver

from .scenario import PASSWORD

pytestmark = pytest.mark.integration

TRIGGERS = ["tr_root_high", "tr_child_avg", "tr_deny_disaster", "tr_tpl"]
OK = set()
EXPECTED_MAIN = {  # recipient -> codes per trigger in TRIGGERS order
    "u_ok": [OK, OK, OK, OK],
    "u_sev": [OK, {"MEDIA_SEVERITY_EXCLUDED"}, OK, {"MEDIA_SEVERITY_EXCLUDED"}],
    "u_mediaoff": [{"MEDIA_DISABLED"}] * 4,
    "u_mtoff": [{"USER_NO_MEDIA"}] * 4,
    "u_nomedia": [{"USER_NO_MEDIA"}] * 4,
    "u_deny": [OK, OK, {"USER_NO_HOST_ACCESS"}, OK],
    "u_tag": [OK, {"USER_NO_HOST_ACCESS"}, {"USER_TAG_FILTER_BLOCKS"}, {"USER_TAG_FILTER_BLOCKS"}],
    "u_disabled": [{"USER_DISABLED"}] * 4,
    "u_norights": [{"USER_NO_HOST_ACCESS"}] * 4,
}


@pytest.fixture(scope="module")
def snap(scenario) -> Snapshot:
    return Snapshot(fetch_raw(scenario.api))


def audit(snap: Snapshot, scenario, modes):
    names = [scenario.name(k) for k in ("a_main", "a_mtoff", "a_formula", "a_nothing")]
    res = Auditor(snap).run(modes, action_filter=names)
    return {a.name.removeprefix(scenario.prefix + "-"): a for a in res.actions}


def pair_codes(op, scenario, mode_report, key_of) -> dict[str, list[set[str]]]:
    out = {}
    rev = {scenario.ids[k]: k for k in EXPECTED_MAIN}  # ids of different object types may coincide
    for r in op.recipients:
        by_key = {k: set(g.codes) for g in r.outcomes for k in g.candidates}
        out[rev[r.userid]] = [by_key.get(key_of(t)) for t in TRIGGERS]
    return out


# ---------------------------------------------------------------------------------------------------------
def test_snapshot_normalized(scenario, snap):
    ids = scenario.ids
    assert set(snap.hosts[ids["h_deny"]].groupids) == {ids["g_root"], ids["g_deny"]}
    assert snap.usergroups[ids["ug_read"]].rights == {ids["g_root"]: C.PERM_READ, ids["g_child"]: C.PERM_READ}
    assert snap.usergroups[ids["ug_deny"]].rights == {ids["g_deny"]: C.PERM_DENY}
    assert [(f.groupid, f.tag, f.value) for f in snap.usergroups[ids["ug_tag"]].tag_filters] == [
        (ids["g_root"], "svc", "db")]
    assert not snap.usergroups[ids["ug_disabled"]].enabled
    assert ids["g_child"] in snap.nested_groupids(ids["g_root"])
    tpl = snap.triggers[ids["tr_tpl"]]
    assert snap.template_chain(tpl) == [ids["t_child"], ids["t_parent"]]
    assert snap.templates[ids["t_child"]].parent_templateids == [ids["t_parent"]]
    assert snap.mediatypes[ids["mt_on"]].message_templates == {(0, 0)}
    u = snap.users[ids["u_sev"]]
    assert u.medias[0].severity == 0b110000 and u.medias[0].sendto == "zaa@example.com"


def test_potential_audit(scenario, snap):
    acts = audit(snap, scenario, [MODE_POTENTIAL])
    ids = scenario.ids

    main_ = acts["a_main"].modes[MODE_POTENTIAL]
    assert set(main_.matched) == {ids[t] for t in TRIGGERS}
    assert not main_.undecided
    problem_op = next(o for o in main_.operations if o.kind == C.OPKIND_PROBLEM)
    got = pair_codes(problem_op, scenario, main_, lambda t: ids[t])
    assert got == EXPECTED_MAIN

    findings = {r.userid: {f.code for f in r.findings} for r in problem_op.recipients}
    assert findings[ids["u_norights"]] == {"COND_HOST_NOT_ACCESSIBLE"}
    assert findings[ids["u_deny"]] == {"COND_HOST_NOT_ACCESSIBLE"}
    assert findings[ids["u_ok"]] == set()
    assert findings[ids["u_nomedia"]] == {"COND_SEVERITY_VS_MEDIA"}
    assert findings[ids["u_sev"]] == {"COND_SEVERITY_PARTIAL"}

    recovery_op = next(o for o in main_.operations if o.kind == C.OPKIND_RECOVERY)
    (rcpt,) = recovery_op.recipients
    assert {c for g in rcpt.outcomes for c in g.codes} == {"MEDIATYPE_NO_MESSAGE_TEMPLATE"}

    mtoff = acts["a_mtoff"].modes[MODE_POTENTIAL]
    assert mtoff.matched == [ids["tr_other_info"]]
    assert [f.code for f in mtoff.operations[0].findings] == ["OP_MEDIATYPE_DISABLED"]

    formula = acts["a_formula"].modes[MODE_POTENTIAL]
    assert set(formula.matched) == {ids["tr_tpl"], ids["tr_root_high"]}

    nothing = acts["a_nothing"].modes[MODE_POTENTIAL]
    assert [f.code for f in nothing.findings] == ["ACTION_MATCHES_NOTHING"]
    assert not nothing.matched and not nothing.undecided
    assert {f.code for f in nothing.operations[0].findings} == {"OP_USERGROUP_EMPTY", "OP_NO_RECIPIENTS"}
    assert all(not a.enabled for a in acts.values())


def _login(scenario, key: str) -> ZabbixAPI:
    api = ZabbixAPI(scenario.api.url, timeout=30)
    api.login(scenario.name(key), PASSWORD)
    return api


def test_permissions_oracle_hosts_and_triggers(scenario, snap):
    """What each test user really sees through the API equals what the resolver computes."""
    ids = scenario.ids
    resolver = PermissionResolver(snap)
    hostids = [ids[h] for h in ("h_root", "h_child", "h_deny", "h_other")]
    cands = [c for c in build_candidates(snap, MODE_POTENTIAL) if set(c.hostids) & set(hostids)]
    for key in ("u_ok", "u_deny", "u_tag", "u_norights"):
        api = _login(scenario, key)
        try:
            seen_hosts = {h["hostid"] for h in api.call("host.get", {"hostids": hostids, "output": ["hostid"]})}
            seen_trigs = {t["triggerid"] for t in api.call("trigger.get", {"hostids": hostids,
                                                                           "output": ["triggerid"]})}
        finally:
            api.call("user.logout", [])
        assert seen_hosts == {h for h in hostids if resolver.can_read_host(ids[key], h)}, key
        assert seen_trigs == {c.key for c in cands if all(resolver.can_read_host(ids[key], h) for h in c.hostids)}, key
    with pytest.raises(ZabbixAPIError):
        _login(scenario, "u_disabled")


@pytest.fixture(scope="module")
def fired(scenario, snap):
    """Generate real problems, but only if no pre-existing enabled action would notify anyone about them."""
    ours = {scenario.ids[k] for k in ("a_main", "a_mtoff", "a_formula", "a_nothing")}
    foreign = [a for a in snap.actions if a.enabled and a.actionid not in ours and a.operations]
    names = [a.actionid for a in foreign]
    if names:
        res = Auditor(snap).run([MODE_POTENTIAL], action_filter=names)
        test_triggers = {scenario.ids[k] for k in [*scenario.trigger_keys(), "tr_tpl"]}
        risky = [a.name for a in res.actions
                 if test_triggers & (set(a.modes[MODE_POTENTIAL].matched) | set(a.modes[MODE_POTENTIAL].undecided))]
        if risky:
            pytest.skip(f"на стенде {scenario.stand} включены действия, которые отправят уведомления о тестовых "
                        f"проблемах: {', '.join(risky)}")
    scenario.fire()
    return Snapshot(fetch_raw(scenario.api))


def test_active_audit(scenario, fired):
    acts = audit(fired, scenario, [MODE_ACTIVE])
    ids = scenario.ids
    event_of = {p.triggerid: p.eventid for p in fired.problems}
    main_ = acts["a_main"].modes[MODE_ACTIVE]
    assert set(main_.matched) == {event_of[ids[t]] for t in TRIGGERS}
    problem_op = next(o for o in main_.operations if o.kind == C.OPKIND_PROBLEM)
    assert pair_codes(problem_op, scenario, main_, lambda t: event_of[ids[t]]) == EXPECTED_MAIN


def test_permissions_oracle_problems_with_tag_filters(scenario, fired):
    ids = scenario.ids
    resolver = PermissionResolver(fired)
    cands = {c.key: c for c in build_candidates(fired, MODE_ACTIVE)
             if c.trigger.triggerid in {ids[k] for k in [*scenario.trigger_keys(), "tr_tpl"]}}
    for key in ("u_ok", "u_deny", "u_tag", "u_norights"):
        api = _login(scenario, key)
        try:
            seen = {p["eventid"] for p in api.call("problem.get", {"eventids": list(cands), "output": ["eventid"]})}
        finally:
            api.call("user.logout", [])
        assert seen == {k for k, c in cands.items() if resolver.access(ids[key], c).code == ACCESS_OK}, key


def test_cli_html(scenario, tmp_path):
    api = scenario.api
    out = tmp_path / "report.html"
    rc = main(["--url", api.url, "--token", api.token, "--secrets", "/nonexistent", "--uncovered",
               "--action", scenario.name("a_main"), "-o", str(out)])
    assert rc == 0  # the test action is disabled, so its FAIL findings do not affect the exit code
    html = out.read_text(encoding="utf-8")
    assert scenario.name("a_main") in html and "USER_NO_HOST_ACCESS" in html
