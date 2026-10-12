"""Three-valued evaluation of action conditions against triggers (potential) and problems (active).

True = matches, False = does not match, None = can not be decided without the actual event
(time period, suppression, unresolved macros).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from typing import Iterable

from . import constants as C
from .macros import Expanded, MacroResolver, literal
from .model import Action, Condition, Snapshot, Trigger
from .period import parse_period

MODE_POTENTIAL = "potential"
MODE_ACTIVE = "active"


def tri_and(values: Iterable[bool | None]) -> bool | None:
    result: bool | None = True
    for v in values:
        if v is False:
            return False
        if v is None:
            result = None
    return result


def tri_or(values: Iterable[bool | None]) -> bool | None:
    result: bool | None = False
    for v in values:
        if v is True:
            return True
        if v is None:
            result = None
    return result


def tri_not(v: bool | None) -> bool | None:
    return None if v is None else not v


@dataclass
class Candidate:
    kind: str  # MODE_POTENTIAL -> trigger, MODE_ACTIVE -> problem
    key: str  # triggerid or eventid
    trigger: Trigger
    name: Expanded
    severity: int
    tags: tuple[tuple[Expanded, Expanded], ...]
    hostids: list[str]
    suppressed: bool | None = None
    clock: int | None = None


def build_candidates(snap: Snapshot, mode: str, resolver: MacroResolver | None = None) -> list[Candidate]:
    if mode == MODE_ACTIVE:
        out = []
        for p in snap.problems:
            trig = snap.triggers.get(p.triggerid)
            if trig is None:
                continue
            out.append(Candidate(MODE_ACTIVE, p.eventid, trig, literal(p.name), p.severity,
                                 tuple((literal(t.tag), literal(t.value)) for t in p.tags), trig.hostids,
                                 p.suppressed, p.clock))
        return out

    resolver = resolver or MacroResolver(snap)
    out = []
    for trig in snap.triggers.values():
        hosts = [snap.hosts.get(h) for h in trig.hostids]
        if not trig.enabled or not hosts or any(h is None or not h.enabled for h in hosts):
            continue
        raw_tags = list(trig.tags)
        for h in hosts:
            raw_tags += list(h.tags) + list(h.inherited_tags)  # type: ignore[union-attr]
        tags: dict[tuple[str, str], tuple[Expanded, Expanded]] = {}
        for t in raw_tags:
            pair = (resolver.expand(t.tag, trig.hostids), resolver.expand(t.value, trig.hostids))
            tags.setdefault((pair[0].text, pair[1].text), pair)
        name = resolver.expand(trig.event_name or trig.description, trig.hostids)
        out.append(Candidate(MODE_POTENTIAL, trig.triggerid, trig, name, trig.priority, tuple(tags.values()),
                             trig.hostids))
    return out


@dataclass
class ConditionResult:
    condition: Condition
    result: bool | None
    note: str = ""


@dataclass
class MatchResult:
    result: bool | None
    details: list[ConditionResult] = field(default_factory=list)

    @property
    def undecided(self) -> list[ConditionResult]:
        return [d for d in self.details if d.result is None]


class ConditionEvaluator:
    def __init__(self, snap: Snapshot, tz: tzinfo | None = None):
        self.snap = snap
        self.tz = tz
        self.macros = MacroResolver(snap)

    # -- single condition --------------------------------------------------
    def condition(self, c: Condition, cand: Candidate) -> ConditionResult:
        fn = {
            C.COND_HOST_GROUP: self._host_group,
            C.COND_HOST: self._host,
            C.COND_TRIGGER: self._trigger,
            C.COND_EVENT_NAME: self._event_name,
            C.COND_SEVERITY: self._severity,
            C.COND_TIME_PERIOD: self._time_period,
            C.COND_TEMPLATE: self._template,
            C.COND_SUPPRESSED: self._suppressed,
            C.COND_EVENT_TAG: self._tag,
            C.COND_EVENT_TAG_VALUE: self._tag_value,
        }.get(c.conditiontype)
        if fn is None:
            return ConditionResult(c, None, f"тип условия {c.conditiontype} не поддерживается")
        result = fn(c, cand)
        if isinstance(result, tuple):
            return ConditionResult(c, result[0], result[1])
        return ConditionResult(c, result)

    @staticmethod
    def _eq(c: Condition, present: bool) -> bool | None:
        if c.operator == C.OP_EQUAL:
            return present
        if c.operator == C.OP_NOT_EQUAL:
            return not present
        return None

    def _host_group(self, c: Condition, cand: Candidate):
        groups = self.snap.nested_groupids(c.value)
        present = any(set(self.snap.hosts[h].groupids) & groups for h in cand.hostids if h in self.snap.hosts)
        return self._eq(c, present)

    def _host(self, c: Condition, cand: Candidate):
        return self._eq(c, c.value in cand.hostids)

    def _trigger(self, c: Condition, cand: Candidate):
        ids = [cand.trigger.triggerid, *self.snap.trigger_ancestors(cand.trigger)]
        return self._eq(c, c.value in ids)

    def _template(self, c: Condition, cand: Candidate):
        return self._eq(c, c.value in self.snap.template_chain(cand.trigger))

    def _event_name(self, c: Condition, cand: Candidate):
        found = cand.name.contains(c.value)
        if c.operator == C.OP_LIKE:
            res = found
        elif c.operator == C.OP_NOT_LIKE:
            res = tri_not(found)
        else:
            return None, "неподдерживаемый оператор"
        return res, ("имя содержит нераскрываемые макросы: " + cand.name.text) if res is None else ""

    def _severity(self, c: Condition, cand: Candidate):
        v, s = int(c.value), cand.severity
        return {C.OP_EQUAL: s == v, C.OP_NOT_EQUAL: s != v, C.OP_MORE_EQUAL: s >= v,
                C.OP_LESS_EQUAL: s <= v}.get(c.operator)

    def _time_period(self, c: Condition, cand: Candidate):
        if cand.clock is None:
            return None, "зависит от времени возникновения проблемы"
        text = self.macros.expand(c.value, [])
        period = parse_period(text.text) if text.exact else None
        if period is None:
            return None, f"не удалось разобрать период «{c.value}»"
        inside = period.contains(datetime.fromtimestamp(cand.clock, self.tz))
        return (inside if c.operator == C.OP_IN else not inside), ""

    def _suppressed(self, c: Condition, cand: Candidate):
        if cand.suppressed is None:
            return None, "зависит от обслуживания на момент события"
        return cand.suppressed if c.operator == C.OP_YES else not cand.suppressed

    def _tag_match(self, exp: Expanded, op: int, value: str) -> bool | None:
        if op in (C.OP_EQUAL, C.OP_NOT_EQUAL):
            return exp.equals(value)
        return exp.contains(value)

    def _tag(self, c: Condition, cand: Candidate):
        found = tri_or(self._tag_match(name, c.operator, c.value) for name, _ in cand.tags)
        res = tri_not(found) if c.operator in (C.OP_NOT_EQUAL, C.OP_NOT_LIKE) else found
        return res, "теги содержат нераскрываемые макросы" if res is None else ""

    def _tag_value(self, c: Condition, cand: Candidate):
        found = tri_or(
            tri_and((name.equals(c.value2), self._tag_match(value, c.operator, c.value)))
            for name, value in cand.tags
        )
        res = tri_not(found) if c.operator in (C.OP_NOT_EQUAL, C.OP_NOT_LIKE) else found
        return res, "теги содержат нераскрываемые макросы" if res is None else ""

    # -- whole filter --------------------------------------------------------
    def action(self, action: Action, cand: Candidate) -> MatchResult:
        details = [self.condition(c, cand) for c in action.conditions]
        return MatchResult(combine(action.evaltype, action.formula, details), details)


def combine(evaltype: int, formula: str, details: list[ConditionResult]) -> bool | None:
    if not details:
        return True
    if evaltype == C.EVALTYPE_AND:
        return tri_and(d.result for d in details)
    if evaltype == C.EVALTYPE_OR:
        return tri_or(d.result for d in details)
    if evaltype == C.EVALTYPE_FORMULA:
        return eval_formula(formula, {d.condition.formulaid: d.result for d in details})
    groups: dict[int, list[bool | None]] = {}
    for d in details:
        groups.setdefault(d.condition.conditiontype, []).append(d.result)
    return tri_and(tri_or(v) for v in groups.values())


_TOKEN = re.compile(r"\s*(\(|\)|and\b|or\b|not\b|[A-Z]+)", re.I)


def eval_formula(formula: str, values: dict[str, bool | None]) -> bool | None:
    """Evaluate a custom expression like ``A and (B or not C)``."""
    tokens: list[str] = []
    pos = 0
    formula = formula.strip()
    while pos < len(formula):
        m = _TOKEN.match(formula, pos)
        if not m:
            raise ValueError(f"bad formula: {formula!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(formula) and formula[pos].isspace():
            pos += 1
    idx = 0

    def peek() -> str | None:
        return tokens[idx].lower() if idx < len(tokens) else None

    def take() -> str:
        nonlocal idx
        if idx >= len(tokens):
            raise ValueError(f"bad formula: {formula!r}")
        idx += 1
        return tokens[idx - 1]

    def expr_or() -> bool | None:
        left = expr_and()
        while peek() == "or":
            take()
            left = tri_or((left, expr_and()))
        return left

    def expr_and() -> bool | None:
        left = expr_not()
        while peek() == "and":
            take()
            left = tri_and((left, expr_not()))
        return left

    def expr_not() -> bool | None:
        if peek() == "not":
            take()
            return tri_not(expr_not())
        return atom()

    def atom() -> bool | None:
        tok = take()
        if tok == "(":
            v = expr_or()
            if take() != ")":
                raise ValueError(f"bad formula: {formula!r}")
            return v
        if tok not in values:
            raise ValueError(f"unknown condition {tok!r} in formula {formula!r}")
        return values[tok]

    result = expr_or()
    if idx != len(tokens):
        raise ValueError(f"bad formula: {formula!r}")
    return result
