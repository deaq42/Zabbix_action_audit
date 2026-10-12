"""In-memory model built from a normalized snapshot (see loader.py for the raw format)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import constants as C


@dataclass(frozen=True)
class Tag:
    tag: str
    value: str

    def __str__(self) -> str:
        return f"{self.tag}:{self.value}" if self.value else self.tag


def _tags(items: list[dict] | None) -> tuple[Tag, ...]:
    return tuple(Tag(t.get("tag", ""), t.get("value", "")) for t in items or [])


@dataclass
class Condition:
    conditiontype: int
    operator: int
    value: str
    value2: str = ""
    formulaid: str = ""


@dataclass
class Operation:
    operationid: str
    kind: str  # constants.OPKIND_*
    operationtype: int
    esc_step_from: int = 1
    esc_step_to: int = 1
    mediatypeid: str = "0"  # "0" = all media types
    default_msg: bool = True
    userids: list[str] = field(default_factory=list)
    usrgrpids: list[str] = field(default_factory=list)
    opconditions: list[dict] = field(default_factory=list)


@dataclass
class Action:
    actionid: str
    name: str
    enabled: bool
    evaltype: int
    formula: str
    conditions: list[Condition]
    operations: list[Operation]
    pause_suppressed: bool
    esc_period: str = ""


@dataclass
class HostGroup:
    groupid: str
    name: str


@dataclass
class Host:
    hostid: str
    host: str
    name: str
    enabled: bool
    groupids: list[str]
    templateids: list[str]  # directly linked templates
    tags: tuple[Tag, ...]
    inherited_tags: tuple[Tag, ...]


@dataclass
class Template:
    templateid: str
    host: str
    name: str
    parent_templateids: list[str]
    tags: tuple[Tag, ...]


@dataclass
class Trigger:
    triggerid: str
    description: str
    event_name: str
    priority: int
    enabled: bool
    templateid: str
    hostids: list[str]
    tags: tuple[Tag, ...]


@dataclass
class TemplateTrigger:
    triggerid: str
    templateid: str
    hostids: list[str]


@dataclass
class Problem:
    eventid: str
    triggerid: str
    name: str
    severity: int
    clock: int
    suppressed: bool
    acknowledged: bool
    tags: tuple[Tag, ...]


@dataclass
class Media:
    mediaid: str
    mediatypeid: str
    sendto: str
    active: bool
    severity: int  # bitmask
    period: str

    def allows(self, severity: int) -> bool:
        return bool(self.severity & (1 << severity))


@dataclass
class User:
    userid: str
    username: str
    fullname: str
    role_type: int
    usrgrpids: list[str]
    medias: list[Media]

    @property
    def is_super_admin(self) -> bool:
        return self.role_type == C.USER_TYPE_SUPER_ADMIN

    @property
    def label(self) -> str:
        return f"{self.username} ({self.fullname})" if self.fullname else self.username


@dataclass
class TagFilter:
    groupid: str
    tag: str
    value: str


@dataclass
class UserGroup:
    usrgrpid: str
    name: str
    enabled: bool
    rights: dict[str, int]  # host groupid -> permission
    tag_filters: list[TagFilter]
    userids: list[str]


@dataclass
class MediaType:
    mediatypeid: str
    name: str
    type: int
    enabled: bool
    message_templates: set[tuple[int, int]]  # (eventsource, recovery)


class Snapshot:
    """Indexes over a normalized raw snapshot."""

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.meta: dict[str, Any] = raw.get("meta", {})
        self.version: str = self.meta.get("version", "")
        self.actions = [_action(a) for a in raw.get("actions", [])]
        self.hostgroups = {g["groupid"]: HostGroup(g["groupid"], g["name"]) for g in raw.get("hostgroups", [])}
        self.hosts = {h["hostid"]: _host(h) for h in raw.get("hosts", [])}
        self.templates = {t["templateid"]: _template(t) for t in raw.get("templates", [])}
        self.triggers = {t["triggerid"]: _trigger(t) for t in raw.get("triggers", [])}
        self.template_triggers = {
            t["triggerid"]: TemplateTrigger(t["triggerid"], t.get("templateid", "0"), list(t.get("hostids", [])))
            for t in raw.get("template_triggers", [])
        }
        self.problems_loaded = "problems" in raw
        self.problems = [_problem(p) for p in raw.get("problems", [])]
        self.users = {u["userid"]: _user(u) for u in raw.get("users", [])}
        self.usergroups = {g["usrgrpid"]: _usergroup(g) for g in raw.get("usergroups", [])}
        self.mediatypes = {m["mediatypeid"]: _mediatype(m) for m in raw.get("mediatypes", [])}
        macros = raw.get("macros", {})
        self.global_macros: dict[str, str | None] = dict(macros.get("global", {}))
        self.host_macros: dict[str, dict[str, str | None]] = {}
        for m in macros.get("host", []):
            self.host_macros.setdefault(m["hostid"], {})[m["macro"]] = m.get("value")

        # derived indexes
        self.group_children: dict[str, set[str]] = _nested_groups(self.hostgroups)

    def nested_groupids(self, groupid: str) -> set[str]:
        """The group itself plus all groups nested under it by name ("A" -> "A/B", "A/B/C")."""
        return {groupid} | self.group_children.get(groupid, set())

    def template_chain(self, trigger: Trigger) -> list[str]:
        """Template ids the trigger is inherited from, nearest first (follows templateid links)."""
        chain: list[str] = []
        seen: set[str] = set()
        tid = trigger.templateid
        while tid and tid != "0" and tid not in seen:
            seen.add(tid)
            parent = self.template_triggers.get(tid)
            if parent is None:
                break
            chain.extend(h for h in parent.hostids if h not in chain)
            tid = parent.templateid
        return chain

    def trigger_ancestors(self, trigger: Trigger) -> list[str]:
        """Trigger ids of template triggers this trigger is inherited from."""
        out: list[str] = []
        tid = trigger.templateid
        while tid and tid != "0" and tid not in out:
            out.append(tid)
            parent = self.template_triggers.get(tid)
            tid = parent.templateid if parent else "0"
        return out

    def users_of_group(self, usrgrpid: str) -> list[str]:
        g = self.usergroups.get(usrgrpid)
        return list(g.userids) if g else []

    def host_label(self, hostid: str) -> str:
        h = self.hosts.get(hostid)
        return h.name if h else f"#{hostid}"

    def group_label(self, groupid: str) -> str:
        g = self.hostgroups.get(groupid)
        return g.name if g else f"#{groupid}"


def _nested_groups(groups: dict[str, HostGroup]) -> dict[str, set[str]]:
    by_name = {g.name: g.groupid for g in groups.values()}
    children: dict[str, set[str]] = {}
    for g in groups.values():
        parts = g.name.split("/")
        for i in range(1, len(parts)):
            parent = by_name.get("/".join(parts[:i]))
            if parent:
                children.setdefault(parent, set()).add(g.groupid)
    return children


def _action(a: dict) -> Action:
    flt = a.get("filter") or {}
    ops: list[Operation] = []
    for kind, key in ((C.OPKIND_PROBLEM, "operations"), (C.OPKIND_RECOVERY, "recovery_operations"),
                      (C.OPKIND_UPDATE, "update_operations")):
        for o in a.get(key) or []:
            msg = o.get("opmessage") or {}
            ops.append(Operation(
                operationid=str(o.get("operationid", "")),
                kind=kind,
                operationtype=int(o.get("operationtype", 0)),
                esc_step_from=int(o.get("esc_step_from", 1) or 1),
                esc_step_to=int(o.get("esc_step_to", 1) or 0),
                mediatypeid=str(msg.get("mediatypeid", "0") or "0"),
                default_msg=str(msg.get("default_msg", "1")) == "1",
                userids=[u["userid"] for u in o.get("opmessage_usr") or []],
                usrgrpids=[g["usrgrpid"] for g in o.get("opmessage_grp") or []],
                opconditions=list(o.get("opconditions") or []),
            ))
    return Action(
        actionid=a["actionid"],
        name=a["name"],
        enabled=str(a.get("status", "0")) == "0",
        evaltype=int(flt.get("evaltype", 0)),
        formula=flt.get("formula", "") or "",
        conditions=[
            Condition(int(c["conditiontype"]), int(c["operator"]), str(c.get("value", "")),
                      str(c.get("value2", "")), str(c.get("formulaid", "")))
            for c in flt.get("conditions") or []
        ],
        operations=ops,
        pause_suppressed=str(a.get("pause_suppressed", "0")) == "1",
        esc_period=a.get("esc_period", ""),
    )


def _host(h: dict) -> Host:
    return Host(h["hostid"], h.get("host", ""), h.get("name") or h.get("host", ""), str(h.get("status", "0")) == "0",
                list(h.get("groupids", [])), list(h.get("templateids", [])), _tags(h.get("tags")),
                _tags(h.get("inheritedTags")))


def _template(t: dict) -> Template:
    return Template(t["templateid"], t.get("host", ""), t.get("name") or t.get("host", ""),
                    list(t.get("parent_templateids", [])), _tags(t.get("tags")))


def _trigger(t: dict) -> Trigger:
    return Trigger(t["triggerid"], t.get("description", ""), t.get("event_name", "") or "",
                   int(t.get("priority", 0)), str(t.get("status", "0")) == "0", str(t.get("templateid", "0") or "0"),
                   list(t.get("hostids", [])), _tags(t.get("tags")))


def _problem(p: dict) -> Problem:
    return Problem(p["eventid"], p["objectid"], p.get("name", ""), int(p.get("severity", 0)), int(p.get("clock", 0)),
                   str(p.get("suppressed", "0")) == "1", str(p.get("acknowledged", "0")) == "1", _tags(p.get("tags")))


def _user(u: dict) -> User:
    full = " ".join(x for x in (u.get("name", ""), u.get("surname", "")) if x)
    medias = [Media(str(m.get("mediaid", "")), str(m["mediatypeid"]), _sendto(m.get("sendto")),
                    str(m.get("active", "0")) == "0", int(m.get("severity", 63)), m.get("period", "") or "")
              for m in u.get("medias") or []]
    return User(u["userid"], u.get("username", ""), full, int(u.get("role_type", 1)), list(u.get("usrgrpids", [])),
                medias)


def _sendto(v: Any) -> str:
    if isinstance(v, list):  # e-mail media keep a list of addresses
        return ", ".join(str(x) for x in v if x)
    return str(v or "")


def _usergroup(g: dict) -> UserGroup:
    return UserGroup(
        g["usrgrpid"], g.get("name", ""), str(g.get("users_status", "0")) == "0",
        {r["id"]: int(r["permission"]) for r in g.get("rights", [])},
        [TagFilter(f["groupid"], f.get("tag", ""), f.get("value", "")) for f in g.get("tag_filters", [])],
        list(g.get("userids", [])),
    )


def _mediatype(m: dict) -> MediaType:
    return MediaType(m["mediatypeid"], m.get("name", ""), int(m.get("type", 0)), str(m.get("status", "0")) == "0",
                     {(int(t["eventsource"]), int(t["recovery"])) for t in m.get("message_templates", [])})
