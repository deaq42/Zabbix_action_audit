from datetime import timezone

import pytest

from builders import RawBuilder
from zabbix_action_audit import constants as C
from zabbix_action_audit.conditions import (MODE_ACTIVE, MODE_POTENTIAL, ConditionEvaluator, build_candidates,
                                            eval_formula)
from zabbix_action_audit.model import Snapshot


@pytest.fixture
def env():
    b = RawBuilder()
    root = b.group("Prod")
    child = b.group("Prod/DB")
    other = b.group("Dev")
    t_base = b.template("T base", tags=[("class", "os")])
    t_app = b.template("T app", parents=[t_base])
    tt_base = b.template_trigger(t_base)
    tt_app = b.template_trigger(t_app, parent=tt_base)
    h1 = b.host("db1", [child], templates=[t_app], tags=[("env", "prod")], inherited=[("class", "os")])
    h2 = b.host("web1", [other])
    h_off = b.host("off", [root], enabled=False)
    b.host_macro(h1, "{$LIMIT}", "90")
    trig_inh = b.trigger([h1], "CPU on {HOST.NAME} > {$LIMIT}", priority=4, templateid=tt_app,
                         tags=[("scope", "perf")])
    trig_plain = b.trigger([h2], "Ping lost", priority=2, tags=[("svc", "{ITEM.VALUE}")])
    b.trigger([h_off], "Never")
    b.trigger([h2], "Disabled", enabled=False)
    return b, dict(root=root, child=child, other=other, t_base=t_base, t_app=t_app, tt_base=tt_base, h1=h1, h2=h2,
                   trig_inh=trig_inh, trig_plain=trig_plain)


def evaluate(b, ids, conditions, evaltype=0, formula="", mode=MODE_POTENTIAL):
    b.action("x", conditions, evaltype=evaltype, formula=formula)
    snap = Snapshot(b.build())
    ev = ConditionEvaluator(snap, timezone.utc)
    action = snap.actions[-1]
    return {c.trigger.triggerid if mode == MODE_POTENTIAL else c.key: ev.action(action, c).result
            for c in build_candidates(snap, mode)}


def test_potential_candidates_skip_disabled_triggers_and_hosts(env):
    b, ids = env
    snap = Snapshot(b.build())
    keys = {c.key for c in build_candidates(snap, MODE_POTENTIAL)}
    assert keys == {ids["trig_inh"], ids["trig_plain"]}


def test_name_expands_host_and_user_macros(env):
    b, ids = env
    snap = Snapshot(b.build())
    cand = next(c for c in build_candidates(snap, MODE_POTENTIAL) if c.key == ids["trig_inh"])
    assert cand.name.exact and cand.name.text == "CPU on DB1 > 90"


def test_event_tags_include_trigger_host_and_template_tags(env):
    b, ids = env
    snap = Snapshot(b.build())
    cand = next(c for c in build_candidates(snap, MODE_POTENTIAL) if c.key == ids["trig_inh"])
    assert {(n.text, v.text) for n, v in cand.tags} == {("scope", "perf"), ("env", "prod"), ("class", "os")}


def test_host_group_includes_nested(env):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_HOST_GROUP, C.OP_EQUAL, ids["root"])])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}


def test_host_group_not_equal(env):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_HOST_GROUP, C.OP_NOT_EQUAL, ids["root"])])
    assert r == {ids["trig_inh"]: False, ids["trig_plain"]: True}


def test_host(env):
    b, ids = env
    assert evaluate(b, ids, [(C.COND_HOST, C.OP_EQUAL, ids["h2"])]) == {ids["trig_inh"]: False, ids["trig_plain"]: True}


def test_trigger_matches_inherited_template_trigger(env):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_TRIGGER, C.OP_EQUAL, ids["tt_base"])])
    assert r[ids["trig_inh"]] is True and r[ids["trig_plain"]] is False


def test_template_condition_follows_nested_templates(env):
    b, ids = env
    for tpl in ("t_base", "t_app"):
        r = evaluate(b, ids, [(C.COND_TEMPLATE, C.OP_EQUAL, ids[tpl])])
        assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}


@pytest.mark.parametrize("op,value,expected", [
    (C.OP_EQUAL, 4, (True, False)), (C.OP_NOT_EQUAL, 4, (False, True)),
    (C.OP_MORE_EQUAL, 3, (True, False)), (C.OP_LESS_EQUAL, 2, (False, True)),
])
def test_severity(env, op, value, expected):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_SEVERITY, op, value)])
    assert (r[ids["trig_inh"]], r[ids["trig_plain"]]) == expected


def test_event_name_like(env):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_EVENT_NAME, C.OP_LIKE, "DB1")])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}
    r = evaluate(b, ids, [(C.COND_EVENT_NAME, C.OP_NOT_LIKE, "Ping")])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}


def test_event_name_with_unresolved_macro_is_unknown_only_when_it_matters():
    b = RawBuilder()
    h = b.host("h", [b.group("G")])
    t = b.trigger([h], "Free space {ITEM.LASTVALUE} on disk")
    for op, value, expected in [(C.OP_LIKE, "space", True), (C.OP_LIKE, "50%", None),
                                (C.OP_NOT_LIKE, "disk", False), (C.OP_NOT_LIKE, "50%", None)]:
        assert evaluate(b, {}, [(C.COND_EVENT_NAME, op, value)])[t] is expected


def test_tags(env):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_EVENT_TAG, C.OP_EQUAL, "env")])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}
    r = evaluate(b, ids, [(C.COND_EVENT_TAG, C.OP_NOT_EQUAL, "env")])
    assert r == {ids["trig_inh"]: False, ids["trig_plain"]: True}
    r = evaluate(b, ids, [(C.COND_EVENT_TAG, C.OP_LIKE, "cop")])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}


def test_tag_value_and_macro_unknown(env):
    b, ids = env
    r = evaluate(b, ids, [(C.COND_EVENT_TAG_VALUE, C.OP_EQUAL, "prod", "env")])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: False}
    r = evaluate(b, ids, [(C.COND_EVENT_TAG_VALUE, C.OP_EQUAL, "nginx", "svc")])
    assert r == {ids["trig_inh"]: False, ids["trig_plain"]: None}
    r = evaluate(b, ids, [(C.COND_EVENT_TAG_VALUE, C.OP_NOT_LIKE, "x", "svc")])
    assert r == {ids["trig_inh"]: True, ids["trig_plain"]: None}


def test_time_and_suppression_unknown_in_potential_and_decided_in_active(env):
    b, ids = env
    # 2023-11-14 22:13:20 UTC is Tuesday
    p_in = b.problem(ids["trig_inh"], "CPU", clock=1_700_000_000, suppressed=True)
    r = evaluate(b, ids, [(C.COND_TIME_PERIOD, C.OP_IN, "1-5,20:00-23:00")])
    assert r[ids["trig_inh"]] is None
    r = evaluate(b, ids, [(C.COND_TIME_PERIOD, C.OP_IN, "1-5,20:00-23:00")], mode=MODE_ACTIVE)
    assert r[p_in] is True
    r = evaluate(b, ids, [(C.COND_TIME_PERIOD, C.OP_NOT_IN, "1-5,20:00-23:00")], mode=MODE_ACTIVE)
    assert r[p_in] is False
    r = evaluate(b, ids, [(C.COND_SUPPRESSED, C.OP_NO, "")], mode=MODE_ACTIVE)
    assert r[p_in] is False
    r = evaluate(b, ids, [(C.COND_SUPPRESSED, C.OP_YES, "")])
    assert r[ids["trig_inh"]] is None


def test_and_or_evaltype_groups_same_types(env):
    b, ids = env
    conds = [(C.COND_HOST, C.OP_EQUAL, ids["h1"]), (C.COND_HOST, C.OP_EQUAL, ids["h2"]),
             (C.COND_SEVERITY, C.OP_MORE_EQUAL, 3)]
    assert evaluate(b, ids, conds, evaltype=C.EVALTYPE_AND_OR) == {ids["trig_inh"]: True, ids["trig_plain"]: False}
    assert evaluate(b, ids, conds, evaltype=C.EVALTYPE_AND) == {ids["trig_inh"]: False, ids["trig_plain"]: False}
    assert evaluate(b, ids, conds, evaltype=C.EVALTYPE_OR) == {ids["trig_inh"]: True, ids["trig_plain"]: True}
    assert evaluate(b, ids, conds, evaltype=C.EVALTYPE_FORMULA, formula="(A or B) and not C") == {
        ids["trig_inh"]: False, ids["trig_plain"]: True}


def test_unknown_propagates_through_kleene_logic(env):
    b, ids = env
    conds = [(C.COND_SUPPRESSED, C.OP_NO, ""), (C.COND_HOST, C.OP_EQUAL, ids["h1"])]
    assert evaluate(b, ids, conds, evaltype=C.EVALTYPE_AND) == {ids["trig_inh"]: None, ids["trig_plain"]: False}
    assert evaluate(b, ids, conds, evaltype=C.EVALTYPE_OR) == {ids["trig_inh"]: True, ids["trig_plain"]: None}


def test_no_conditions_match_everything(env):
    b, ids = env
    assert set(evaluate(b, ids, []).values()) == {True}


@pytest.mark.parametrize("formula,expected", [
    ("A and B", False), ("A or B", True), ("not B", True), ("A and (B or C)", None), ("not (A and C)", None),
    ("A AND NOT B", True),
])
def test_formula(formula, expected):
    assert eval_formula(formula, {"A": True, "B": False, "C": None}) is expected


@pytest.mark.parametrize("formula", ["A and", "(A or B", "A B", "A and Z"])
def test_formula_errors(formula):
    with pytest.raises(ValueError):
        eval_formula(formula, {"A": True, "B": False})
