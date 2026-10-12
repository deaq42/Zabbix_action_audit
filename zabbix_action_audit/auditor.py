"""Runs all checks and produces an AuditResult (plain dataclasses, serializable to JSON)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from typing import Any

from . import constants as C
from . import media as M
from . import permissions as P
from .conditions import (MODE_ACTIVE, MODE_POTENTIAL, Candidate, ConditionEvaluator, ConditionResult, build_candidates,
                         combine)
from .model import Action, Condition, Operation, Snapshot

OK, INFO, WARN, FAIL = "OK", "INFO", "WARN", "FAIL"
LEVEL_ORDER = {OK: 0, INFO: 1, WARN: 2, FAIL: 3}

LEVELS = {
    P.USER_DISABLED: FAIL,
    P.USER_NO_HOST_ACCESS: FAIL,
    P.USER_TAG_FILTER_BLOCKS: FAIL,
    P.ACCESS_UNKNOWN: WARN,
    M.USER_NO_MEDIA: FAIL,
    M.MEDIA_DISABLED: FAIL,
    M.MEDIATYPE_DISABLED: FAIL,
    M.MEDIATYPE_MISSING: FAIL,
    M.MEDIA_SEVERITY_EXCLUDED: FAIL,
    M.MEDIA_EMPTY_SENDTO: WARN,
    M.MEDIATYPE_NO_MESSAGE_TEMPLATE: WARN,
    M.MEDIA_PERIOD_EXCLUDED: WARN,
    M.MEDIA_PERIOD_LIMITED: INFO,
    "ACTION_DISABLED": INFO,
    "ACTION_NO_SEND_OPS": INFO,
    "ACTION_PAUSE_SUPPRESSED": INFO,
    "ACTION_MATCHES_NOTHING": WARN,
    "ACTION_ONLY_UNDECIDED": WARN,
    "ACTION_NO_PROBLEMS": INFO,
    "ACTION_FORMULA_INVALID": FAIL,
    "COND_REF_MISSING": WARN,
    "COND_UNSUPPORTED": WARN,
    "COND_HOST_NOT_ACCESSIBLE": WARN,
    "COND_SEVERITY_VS_MEDIA": WARN,
    "COND_SEVERITY_PARTIAL": INFO,
    "OP_NO_RECIPIENTS": FAIL,
    "OP_USERGROUP_EMPTY": WARN,
    "OP_USER_MISSING": WARN,
    "OP_MEDIATYPE_DISABLED": FAIL,
    "OP_NOTIFY_INVOLVED": INFO,
    "OP_REMOTE_COMMAND": INFO,
}

DESCRIPTIONS = {
    P.USER_DISABLED: "Пользователь отключён (состоит в группе со статусом «Отключено»)",
    P.USER_NO_HOST_ACCESS: "Нет прав на чтение хоста проблемы",
    P.USER_TAG_FILTER_BLOCKS: "Проблема скрыта tag-фильтрами групп пользователя",
    P.ACCESS_UNKNOWN: "Видимость по tag-фильтрам зависит от значений, известных только в момент события",
    M.USER_NO_MEDIA: "У пользователя нет медиа нужного типа",
    M.MEDIA_DISABLED: "Медиа пользователя отключено",
    M.MEDIATYPE_DISABLED: "Тип медиа отключён",
    M.MEDIATYPE_MISSING: "Тип медиа не существует",
    M.MEDIA_SEVERITY_EXCLUDED: "Важность проблемы не включена в медиа пользователя",
    M.MEDIA_EMPTY_SENDTO: "Пустой адрес получателя",
    M.MEDIATYPE_NO_MESSAGE_TEMPLATE: "В типе медиа нет шаблона сообщения для этого вида операции",
    M.MEDIA_PERIOD_EXCLUDED: "Проблема возникла вне периода активности медиа",
    M.MEDIA_PERIOD_LIMITED: "Медиа активно не круглосуточно",
}


def level_of(codes: list[str] | tuple[str, ...]) -> str:
    return max((LEVELS.get(c, WARN) for c in codes), key=LEVEL_ORDER.__getitem__, default=OK)


@dataclass
class Finding:
    level: str
    code: str
    message: str


def finding(code: str, message: str) -> Finding:
    return Finding(LEVELS.get(code, WARN), code, message)


@dataclass
class OutcomeGroup:
    level: str
    codes: list[str]
    details: list[str]
    candidates: list[str]


@dataclass
class RecipientReport:
    userid: str
    label: str
    via: list[str]
    findings: list[Finding] = field(default_factory=list)
    outcomes: list[OutcomeGroup] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class OperationReport:
    operationid: str
    kind: str
    title: str
    context: str
    findings: list[Finding] = field(default_factory=list)
    recipients: list[RecipientReport] = field(default_factory=list)


@dataclass
class ModeReport:
    mode: str
    matched: list[str] = field(default_factory=list)
    undecided: dict[str, list[str]] = field(default_factory=dict)  # candidate key -> notes
    findings: list[Finding] = field(default_factory=list)
    operations: list[OperationReport] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class ActionReport:
    actionid: str
    name: str
    enabled: bool
    conditions: list[str]
    evaltype: str
    findings: list[Finding] = field(default_factory=list)
    modes: dict[str, ModeReport] = field(default_factory=dict)

    @property
    def worst(self) -> str:
        levels = [f.level for f in self.findings]
        for m in self.modes.values():
            levels += [f.level for f in m.findings]
            levels += [lvl for lvl, n in m.counts.items() if n]
            for op in m.operations:
                levels += [f.level for f in op.findings]
                for r in op.recipients:
                    levels += [f.level for f in r.findings]
        return max(levels, key=LEVEL_ORDER.__getitem__, default=OK)


@dataclass
class AuditResult:
    meta: dict[str, Any]
    modes: list[str]
    actions: list[ActionReport]
    candidates: dict[str, dict[str, dict[str, Any]]]  # mode -> key -> summary
    uncovered: dict[str, list[str]]
    descriptions: dict[str, str]

    def count(self, level: str, *, enabled_only: bool = True) -> int:
        total = 0
        for a in self.actions:
            if enabled_only and not a.enabled:
                continue
            total += sum(1 for f in a.findings if f.level == level)
            for m in a.modes.values():
                total += m.counts.get(level, 0) + sum(1 for f in m.findings if f.level == level)
                for op in m.operations:
                    total += sum(1 for f in op.findings if f.level == level)
                    total += sum(1 for r in op.recipients for f in r.findings if f.level == level)
        return total


EVALTYPE_NAMES = {0: "И/ИЛИ", 1: "И", 2: "ИЛИ", 3: "Формула"}


class Auditor:
    def __init__(self, snap: Snapshot, *, tz: tzinfo | None = None):
        self.snap = snap
        self.tz = tz
        self.evaluator = ConditionEvaluator(snap, tz)
        self.perms = P.PermissionResolver(snap)
        self.media = M.MediaChecker(snap, tz)
        self._media_cache: dict[tuple, M.MediaResult] = {}

    # -- public ------------------------------------------------------------
    def run(self, modes: list[str], *, action_filter: list[str] | None = None, skip_disabled: bool = False,
            uncovered: bool = False) -> AuditResult:
        if MODE_ACTIVE in modes and not self.snap.problems_loaded:
            modes = [m for m in modes if m != MODE_ACTIVE]
        candidates = {mode: build_candidates(self.snap, mode, self.evaluator.macros) for mode in modes}
        actions = [a for a in self.snap.actions if self._selected(a, action_filter)]
        if skip_disabled:
            actions = [a for a in actions if a.enabled]

        reports = []
        matches: dict[str, dict[str, dict[str, bool | None]]] = {m: {} for m in modes}
        for action in actions:
            report, per_mode = self._action(action, candidates)
            reports.append(report)
            for mode, res in per_mode.items():
                matches[mode][action.actionid] = res
        reports.sort(key=lambda r: (not r.enabled, -LEVEL_ORDER[r.worst], r.name.lower()))

        uncov: dict[str, list[str]] = {}
        if uncovered:
            senders = {a.actionid for a in self.snap.actions if a.enabled and self._sends(a)}
            for mode in modes:
                done = matches[mode]
                uncov[mode] = [c.key for c in candidates[mode] if all(
                    (done[a.actionid][c.key] if a.actionid in done else self._match(a, c)) is False
                    for a in self.snap.actions if a.actionid in senders)]

        meta = dict(self.snap.meta)
        meta["audited"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return AuditResult(
            meta=meta, modes=modes, actions=reports,
            candidates={mode: {c.key: self._summary(c) for c in candidates[mode]} for mode in modes},
            uncovered=uncov,
            descriptions=dict(DESCRIPTIONS),
        )

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _selected(action: Action, flt: list[str] | None) -> bool:
        if not flt:
            return True
        return any(f == action.actionid or f.lower() == action.name.lower() for f in flt)

    @staticmethod
    def _sends(action: Action) -> bool:
        return any(o.operationtype == C.OPTYPE_MESSAGE for o in action.operations)

    def _match(self, action: Action, cand: Candidate) -> bool | None:
        try:
            return self.evaluator.action(action, cand).result
        except ValueError:
            return None

    def _summary(self, c: Candidate) -> dict[str, Any]:
        base = self.snap.meta.get("frontend", "")
        url = (f"{base}tr_events.php?triggerid={c.trigger.triggerid}&eventid={c.key}" if c.kind == MODE_ACTIVE
               else f"{base}zabbix.php?action=problem.view&filter_set=1&triggerids%5B%5D={c.trigger.triggerid}")
        return {
            "key": c.key,
            "triggerid": c.trigger.triggerid,
            "name": c.name.text,
            "severity": c.severity,
            "hosts": [self.snap.host_label(h) for h in c.hostids],
            "clock": c.clock,
            "suppressed": c.suppressed,
            "url": url,
        }

    def describe_condition(self, c: Condition) -> str:
        name = C.CONDITION_NAMES.get(c.conditiontype, f"Условие {c.conditiontype}")
        op = C.OPERATOR_NAMES.get(c.operator, str(c.operator))
        value = c.value
        if c.conditiontype == C.COND_HOST_GROUP:
            value = self.snap.group_label(c.value)
        elif c.conditiontype == C.COND_HOST:
            value = self.snap.host_label(c.value)
        elif c.conditiontype == C.COND_TEMPLATE:
            t = self.snap.templates.get(c.value)
            value = t.name if t else f"#{c.value}"
        elif c.conditiontype == C.COND_TRIGGER:
            t = self.snap.triggers.get(c.value)
            value = (f"{t.description} ({', '.join(self.snap.host_label(h) for h in t.hostids)})" if t
                     else ("шаблонный триггер #" if c.value in self.snap.template_triggers else "#") + c.value)
        elif c.conditiontype == C.COND_SEVERITY:
            value = C.SEVERITY_NAMES[int(c.value)] if c.value.isdigit() and int(c.value) < 6 else c.value
        elif c.conditiontype == C.COND_EVENT_TAG_VALUE:
            return f"{c.formulaid}: {name} «{c.value2}» {op} «{c.value}»"
        elif c.conditiontype == C.COND_SUPPRESSED:
            return f"{c.formulaid}: {name}: {op}"
        return f"{c.formulaid}: {name} {op} «{value}»"

    def _missing_refs(self, action: Action) -> list[Finding]:
        out = []
        for c in action.conditions:
            missing = (
                (c.conditiontype == C.COND_HOST_GROUP and c.value not in self.snap.hostgroups)
                or (c.conditiontype == C.COND_HOST and c.value not in self.snap.hosts)
                or (c.conditiontype == C.COND_TEMPLATE and c.value not in self.snap.templates)
                or (c.conditiontype == C.COND_TRIGGER and c.value not in self.snap.triggers
                    and c.value not in self.snap.template_triggers)
            )
            if missing:
                out.append(finding("COND_REF_MISSING", f"Условие {c.formulaid} ссылается на несуществующий объект "
                                                       f"#{c.value}"))
            elif c.conditiontype not in C.CONDITION_NAMES:
                out.append(finding("COND_UNSUPPORTED", f"Условие {c.formulaid}: тип {c.conditiontype} не "
                                                       "поддерживается аудитом, результат — «не определено»"))
        return out

    def _allowed_severities(self, action: Action) -> set[int]:
        """Severities the filter can let through, judging by the severity conditions alone."""
        allowed = set()
        for s in range(6):
            details = [ConditionResult(c, self.evaluator._severity(c, _SeverityProbe(s))  # type: ignore[arg-type]
                                       if c.conditiontype == C.COND_SEVERITY else None)
                       for c in action.conditions]
            try:
                if combine(action.evaltype, action.formula, details) is not False:
                    allowed.add(s)
            except ValueError:
                allowed.add(s)
        return allowed

    # -- action --------------------------------------------------------------
    def _action(self, action: Action, candidates: dict[str, list[Candidate]]
                ) -> tuple[ActionReport, dict[str, dict[str, bool | None]]]:
        report = ActionReport(action.actionid, action.name, action.enabled,
                              [self.describe_condition(c) for c in action.conditions],
                              EVALTYPE_NAMES.get(action.evaltype, str(action.evaltype))
                              + (f": {action.formula}" if action.evaltype == C.EVALTYPE_FORMULA else ""))
        if not action.enabled:
            report.findings.append(finding("ACTION_DISABLED", "Действие отключено — уведомления не отправляются"))
        if not self._sends(action):
            report.findings.append(finding("ACTION_NO_SEND_OPS", "В действии нет операций отправки сообщений"))
        if action.pause_suppressed:
            report.findings.append(finding("ACTION_PAUSE_SUPPRESSED",
                                           "Эскалация приостанавливается для подавленных проблем (обслуживание)"))
        report.findings += self._missing_refs(action)
        formula_ok = True
        if action.evaltype == C.EVALTYPE_FORMULA:
            try:
                combine(action.evaltype, action.formula,
                        [ConditionResult(c, True) for c in action.conditions])
            except ValueError as e:
                formula_ok = False
                report.findings.append(finding("ACTION_FORMULA_INVALID", f"Некорректная формула: {e}"))

        allowed = self._allowed_severities(action)
        per_mode: dict[str, dict[str, bool | None]] = {}
        for mode, cands in candidates.items():
            mr = ModeReport(mode)
            results: dict[str, bool | None] = {}
            matched: list[Candidate] = []
            for cand in cands:
                res = self.evaluator.action(action, cand) if formula_ok else None
                value = res.result if res else None
                results[cand.key] = value
                if value is True:
                    mr.matched.append(cand.key)
                    matched.append(cand)
                elif value is None:
                    notes = [f"{d.condition.formulaid}: {d.note}" for d in res.undecided] if res else ["формула"]
                    mr.undecided[cand.key] = notes or ["не определено"]
                    matched.append(cand)
            per_mode[mode] = results
            if not mr.matched and mr.undecided and mode == MODE_POTENTIAL:
                mr.findings.append(finding("ACTION_ONLY_UNDECIDED",
                                           f"Определённо не подходит ни один триггер; {len(mr.undecided)} зависят "
                                           "от значений, известных только в момент события"))
            if not matched:
                if mode == MODE_POTENTIAL:
                    mr.findings.append(finding("ACTION_MATCHES_NOTHING",
                                               "Ни один включённый триггер не подпадает под условия действия"))
                else:
                    mr.findings.append(finding("ACTION_NO_PROBLEMS", "Нет текущих проблем, подпадающих под действие"))
            for op in action.operations:
                mr.operations.append(self._operation(action, op, matched, mr.undecided, allowed, mode))
            counts = {OK: 0, INFO: 0, WARN: 0, FAIL: 0}
            for op in mr.operations:
                for r in op.recipients:
                    for lvl, n in r.counts.items():
                        counts[lvl] += n
            mr.counts = counts
            report.modes[mode] = mr
        return report, per_mode

    # -- operation -----------------------------------------------------------
    def _operation(self, action: Action, op: Operation, matched: list[Candidate], undecided: dict[str, list[str]],
                   allowed: set[int], mode: str) -> OperationReport:
        steps = ""
        if op.kind == C.OPKIND_PROBLEM:
            to = "∞" if op.esc_step_to == 0 else str(op.esc_step_to)
            steps = f"шаги {op.esc_step_from}–{to}"
        ack = [("только неподтверждённые" if str(c.get("value")) == "0" else "только подтверждённые")
               for c in op.opconditions if str(c.get("conditiontype")) == "14"]
        context = ", ".join(x for x in (C.OPKIND_NAMES[op.kind], steps, *ack) if x)

        if op.operationtype == C.OPTYPE_COMMAND:
            rep = OperationReport(op.operationid, op.kind, "Удалённая команда", context)
            rep.findings.append(finding("OP_REMOTE_COMMAND", "Удалённая команда — получатели не проверяются"))
            return rep
        if op.operationtype in (C.OPTYPE_RECOVERY_MESSAGE, C.OPTYPE_UPDATE_MESSAGE):
            rep = OperationReport(op.operationid, op.kind, "Уведомить всех участников", context)
            rep.findings.append(finding("OP_NOTIFY_INVOLVED",
                                        "Получатели определяются в момент события (те, кто получил уведомления "
                                        "о проблеме)"))
            return rep

        mtname = self.media.mediatype_name(op.mediatypeid)
        rep = OperationReport(op.operationid, op.kind, f"Отправить сообщение через: {mtname}", context)
        mt = self.snap.mediatypes.get(op.mediatypeid)
        if op.mediatypeid != "0" and mt is not None and not mt.enabled:
            rep.findings.append(finding("OP_MEDIATYPE_DISABLED", f"Тип медиа «{mt.name}» отключён"))

        recipients: dict[str, list[str]] = {}
        for uid in op.userids:
            recipients.setdefault(uid, []).append("напрямую")
        for gid in op.usrgrpids:
            g = self.snap.usergroups.get(gid)
            if g is None:
                rep.findings.append(finding("OP_USERGROUP_EMPTY", f"Группа пользователей #{gid} не существует"))
                continue
            if not g.userids:
                rep.findings.append(finding("OP_USERGROUP_EMPTY", f"Группа пользователей «{g.name}» пуста"))
            for uid in g.userids:
                recipients.setdefault(uid, []).append(f"группа «{g.name}»")
        if not recipients:
            rep.findings.append(finding("OP_NO_RECIPIENTS", "У операции нет ни одного получателя"))

        for uid, via in recipients.items():
            user = self.snap.users.get(uid)
            if user is None:
                rep.findings.append(finding("OP_USER_MISSING", f"Пользователь #{uid} не существует"))
                continue
            rep.recipients.append(self._recipient(action, op, user, via, matched, allowed))
        return rep

    def _recipient(self, action: Action, op: Operation, user, via: list[str], matched: list[Candidate],
                   allowed: set[int]) -> RecipientReport:
        rr = RecipientReport(user.userid, user.label, via)
        rr.findings += self._condition_access(action, user)
        rr.findings += self._severity_coverage(op, user, allowed)

        groups: dict[tuple[str, ...], OutcomeGroup] = {}
        for cand in matched:
            codes, details = self._pair(op, user, cand)
            key = tuple(sorted(set(codes)))
            g = groups.get(key)
            if g is None:
                g = groups[key] = OutcomeGroup(level_of(key), list(key), [], [])
            g.candidates.append(cand.key)
            for d in details:
                if d not in g.details and len(g.details) < 30:
                    g.details.append(d)
        rr.outcomes = sorted(groups.values(), key=lambda g: (-LEVEL_ORDER[g.level], -len(g.candidates)))
        rr.counts = {lvl: sum(len(g.candidates) for g in rr.outcomes if g.level == lvl) for lvl in LEVEL_ORDER}
        return rr

    def _pair(self, op: Operation, user, cand: Candidate) -> tuple[list[str], list[str]]:
        codes, details = [], []
        access = self.perms.access(user.userid, cand)
        if not access.ok:
            codes.append(access.code)
            details.append(access.detail)
        key = (user.userid, op.mediatypeid, cand.severity, op.kind, op.default_msg, cand.clock)
        res = self._media_cache.get(key)
        if res is None:
            res = self._media_cache[key] = self.media.check(user, op.mediatypeid, cand.severity, opkind=op.kind,
                                                            default_msg=op.default_msg, clock=cand.clock)
        for i in res.issues:
            codes.append(i.code)
            details.append(i.detail)
        return codes, details

    def _condition_access(self, action: Action, user) -> list[Finding]:
        """Hosts and host groups named in "=" conditions must be readable by the recipient."""
        if user.is_super_admin or self.perms.disabled_by(user):
            return []
        out = []
        for c in action.conditions:
            if c.operator != C.OP_EQUAL:
                continue
            if c.conditiontype == C.COND_HOST and c.value in self.snap.hosts:
                if not self.perms.can_read_host(user.userid, c.value):
                    out.append(finding("COND_HOST_NOT_ACCESSIBLE", f"Нет прав на хост «{self.snap.host_label(c.value)}» "
                                                                   f"из условия {c.formulaid}"))
            elif c.conditiontype == C.COND_HOST_GROUP and c.value in self.snap.hostgroups:
                groups = self.snap.nested_groupids(c.value)
                hosts = [h for h in self.snap.hosts.values() if set(h.groupids) & groups]
                readable = [h for h in hosts if self.perms.can_read_host(user.userid, h.hostid)]
                if len(readable) < len(hosts) or not any(self.perms.can_read_group(user.userid, g) for g in groups):
                    out.append(finding("COND_HOST_NOT_ACCESSIBLE",
                                       f"Группа «{self.snap.group_label(c.value)}» из условия {c.formulaid}: "
                                       f"доступно хостов {len(readable)} из {len(hosts)}"))
        return out

    def _severity_coverage(self, op: Operation, user, allowed: set[int]) -> list[Finding]:
        if not allowed:
            return []
        usable = set()
        for m in user.medias:
            mt = self.snap.mediatypes.get(m.mediatypeid)
            if (op.mediatypeid in ("0", m.mediatypeid)) and m.active and mt and mt.enabled:
                usable |= {s for s in range(6) if m.allows(s)}
        missing = sorted(allowed - usable)
        if not missing:
            return []
        names = ", ".join(C.SEVERITY_NAMES[s] for s in missing)
        if set(missing) == allowed:
            return [finding("COND_SEVERITY_VS_MEDIA", f"Ни одна из важностей, пропускаемых действием, не будет "
                                                      f"доставлена этому пользователю ({names})")]
        return [finding("COND_SEVERITY_PARTIAL", f"Не будут доставлены важности: {names}")]


@dataclass
class _SeverityProbe:
    severity: int
