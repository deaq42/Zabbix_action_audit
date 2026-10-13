"""Fetches everything the audit needs from the API and normalizes it.

The normalized "raw" snapshot uses one shape for every Zabbix version, so the rest of the
application never branches on version. Differences between 6.0 LTS and 7.x handled here:

==========================  ======================  ==========================
what                        6.0 / 6.2               6.4 / 7.x
==========================  ======================  ==========================
host groups of a host       selectGroups → groups   selectHostGroups → hostgroups
user group rights           selectRights → rights   selectHostGroupRights → hostgroup_rights
check who owns the token    checkAuthentication     checkAuthentication {token}
                            {sessionid}
==========================  ======================  ==========================

Older versions silently ignore unknown ``select*`` options, so the request is built per version.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import constants as C
from .api import ZabbixAPI, ZabbixAPIError, ZabbixTransportError, frontend_base

log = logging.getLogger(__name__)

SNAPSHOT_FORMAT = 1


DEFAULT_CHUNK = 100  # hosts per request for the heavy calls


def fetch_raw(api: ZabbixAPI, *, with_problems: bool = True, action_filter: list[str] | None = None,
              chunk: int = DEFAULT_CHUNK) -> dict[str, Any]:
    """Loads the snapshot. Heavy objects (hosts, triggers, macros, problems) are requested in chunks of hosts,
    and a chunk the frontend fails on (HTTP 5xx, timeout) is split in half and retried.

    With ``action_filter`` only hosts that can match the selected actions are loaded (``meta.scope``)."""
    new_groups = api.at_least(6, 2)
    raw: dict[str, Any] = {
        "meta": {
            "format": SNAPSHOT_FORMAT,
            "version": api.version_str or ".".join(map(str, api.version)),
            "frontend": frontend_base(api.url),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scope": None,
        }
    }
    log.info("Zabbix %s", raw["meta"]["version"])
    raw["meta"]["token_user"] = _token_user(api)
    get = _Chunked(api, chunk)

    raw["actions"] = api.call("action.get", {
        "output": ["actionid", "name", "status", "esc_period", "pause_suppressed"],
        "filter": {"eventsource": C.EVENTSOURCE_TRIGGERS},
        "selectFilter": "extend",
        "selectOperations": "extend",
        "selectRecoveryOperations": "extend",
        "selectUpdateOperations": "extend",
    })
    raw["hostgroups"] = api.call("hostgroup.get", {"output": ["groupid", "name"]})

    hostids: list[str] | None = None
    if action_filter:
        selected = [a for a in raw["actions"] if any(
            f == a["actionid"] or f.lower() == a["name"].lower() for f in action_filter)]
        hostids = _scope_hostids(api, selected, raw["hostgroups"])
        if hostids is not None:
            hostids = sorted(set(hostids) | _referenced_hostids(api, selected), key=int)
            raw["meta"]["scope"] = {"actions": [a["actionid"] for a in selected], "hosts": len(hostids)}
            log.info("Выбранные действия ограничены %d хостами — загружаются только они", len(hostids))
    if hostids is None:
        hostids = [h["hostid"] for h in api.call("host.get", {"output": ["hostid"]})]
    log.info("Хостов: %d", len(hostids))

    group_key = "hostgroups" if new_groups else "groups"
    hosts = get("host.get", {
        "output": ["hostid", "host", "name", "status", "maintenance_status"],
        "selectHostGroups" if new_groups else "selectGroups": ["groupid"],
        "selectParentTemplates": ["templateid"],
        "selectTags": ["tag", "value"],
        "selectInheritedTags": ["tag", "value"],
    }, "hostids", hostids)
    raw["hosts"] = [{
        "hostid": h["hostid"], "host": h["host"], "name": h.get("name", ""), "status": h["status"],
        "maintenance": h.get("maintenance_status"),
        "groupids": [g["groupid"] for g in h.get(group_key, [])],
        "templateids": [t["templateid"] for t in h.get("parentTemplates", [])],
        "tags": h.get("tags", []), "inheritedTags": h.get("inheritedTags", []),
    } for h in hosts]

    templateids = [t["templateid"] for t in api.call("template.get", {"output": ["templateid"]})]
    templates = get("template.get", {
        "output": ["templateid", "host", "name"],
        "selectParentTemplates": ["templateid"],
        "selectTags": ["tag", "value"],
    }, "templateids", templateids)
    raw["templates"] = [{
        "templateid": t["templateid"], "host": t["host"], "name": t.get("name", ""),
        "parent_templateids": [p["templateid"] for p in t.get("parentTemplates", [])],
        "tags": t.get("tags", []),
    } for t in templates]

    triggers = get("trigger.get", {
        "output": ["triggerid", "description", "event_name", "priority", "status", "templateid"],
        "templated": False,
        "selectHosts": ["hostid"],
        "selectTags": ["tag", "value"],
    }, "hostids", hostids, unique="triggerid")
    raw["triggers"] = [{
        "triggerid": t["triggerid"], "description": t["description"], "event_name": t.get("event_name", ""),
        "priority": t["priority"], "status": t["status"], "templateid": t.get("templateid", "0"),
        "hostids": [h["hostid"] for h in t.get("hosts", [])], "tags": t.get("tags", []),
    } for t in triggers]
    log.info("Триггеров: %d", len(raw["triggers"]))

    ttriggers = get("trigger.get", {
        "output": ["triggerid", "templateid"], "templated": True, "selectHosts": ["hostid"],
    }, "hostids", templateids, unique="triggerid")
    raw["template_triggers"] = [{
        "triggerid": t["triggerid"], "templateid": t.get("templateid", "0"),
        "hostids": [h["hostid"] for h in t.get("hosts", [])],
    } for t in ttriggers]

    if with_problems:
        raw["problems"] = get("problem.get", {
            "output": ["eventid", "objectid", "name", "severity", "clock", "suppressed", "acknowledged"],
            "source": 0, "object": 0, "selectTags": ["tag", "value"],
        }, "hostids", hostids, unique="eventid")
        log.info("Текущих проблем: %d", len(raw["problems"]))

    users = api.call("user.get", {
        "output": ["userid", "username", "name", "surname"],
        "selectRole": ["type"],
        "selectUsrgrps": ["usrgrpid"],
        "selectMedias": ["mediaid", "mediatypeid", "sendto", "active", "severity", "period"],
    })
    raw["users"] = [{
        "userid": u["userid"], "username": u["username"], "name": u.get("name", ""), "surname": u.get("surname", ""),
        "role_type": (u.get("role") or {}).get("type", "1"),
        "usrgrpids": [g["usrgrpid"] for g in u.get("usrgrps", [])],
        "medias": u.get("medias", []),
    } for u in users]

    rights_key = "hostgroup_rights" if new_groups else "rights"
    groups = api.call("usergroup.get", {
        "output": ["usrgrpid", "name", "users_status"],
        "selectHostGroupRights" if new_groups else "selectRights": ["id", "permission"],
        "selectTagFilters": ["groupid", "tag", "value"],
        "selectUsers": ["userid"],
    })
    raw["usergroups"] = [{
        "usrgrpid": g["usrgrpid"], "name": g["name"], "users_status": g["users_status"],
        "rights": g.get(rights_key, []), "tag_filters": g.get("tag_filters", []),
        "userids": [u["userid"] for u in g.get("users", [])],
    } for g in groups]

    mediatypes = api.call("mediatype.get", {
        "output": ["mediatypeid", "name", "type", "status"],
        "selectMessageTemplates": ["eventsource", "recovery"],
    })
    raw["mediatypes"] = [{
        "mediatypeid": m["mediatypeid"], "name": m["name"], "type": m["type"], "status": m["status"],
        "message_templates": m.get("message_templates", []),
    } for m in mediatypes]

    gmacros = api.call("usermacro.get", {"globalmacro": True, "output": ["macro", "value", "type"]})
    hmacros = get("usermacro.get", {"output": ["hostid", "macro", "value", "type"]}, "hostids",
                  hostids + templateids)
    raw["macros"] = {
        "global": {m["macro"]: _macro_value(m) for m in gmacros},
        "host": [{"hostid": m["hostid"], "macro": m["macro"], "value": _macro_value(m)} for m in hmacros],
    }
    return raw


class _Chunked:
    """Calls ``method`` for slices of an id list; a slice the frontend fails on is split in half and retried."""

    def __init__(self, api: ZabbixAPI, size: int):
        self.api = api
        self.size = max(1, size)

    def __call__(self, method: str, params: dict, key: str, ids: list[str], *, unique: str | None = None) -> list:
        out: list = []
        seen: set[str] = set()
        queue = [ids[i:i + self.size] for i in range(0, len(ids), self.size)]
        total, done = len(ids), 0
        while queue:
            part = queue.pop(0)
            try:
                result = self.api.call(method, {**params, key: part})
            except ZabbixTransportError as e:
                if len(part) == 1:
                    raise ZabbixTransportError(method, f"{e.reason} даже для одного объекта ({key}={part[0]}); "
                                                       "увеличьте memory_limit/max_execution_time PHP или --timeout"
                                               ) from e
                half = len(part) // 2
                queue[:0] = [part[:half], part[half:]]
                log.warning("%s: %s на порции из %d, повтор порциями по %d", method, e.reason, len(part), half)
                continue
            done += len(part)
            for obj in result:
                if unique:
                    if obj[unique] in seen:
                        continue
                    seen.add(obj[unique])
                out.append(obj)
            if total > self.size:
                log.info("%s: %d/%d", method, done, total)
        return out


def _referenced_hostids(api: ZabbixAPI, actions: list[dict]) -> set[str]:
    """Hosts named in host conditions and hosts of triggers named in trigger conditions (any operator),
    so that references are not reported as missing just because they are outside the scope."""
    hosts, triggers = set(), set()
    for a in actions:
        for c in (a.get("filter") or {}).get("conditions") or []:
            if int(c["conditiontype"]) == C.COND_HOST:
                hosts.add(str(c["value"]))
            elif int(c["conditiontype"]) == C.COND_TRIGGER:
                triggers.add(str(c["value"]))
    if triggers:
        for t in api.call("trigger.get", {"triggerids": sorted(triggers), "templated": False,
                                          "output": ["triggerid"], "selectHosts": ["hostid"]}):
            hosts |= {h["hostid"] for h in t["hosts"]}
    if hosts:  # only existing, non-template hosts
        hosts = {h["hostid"] for h in api.call("host.get", {"hostids": sorted(hosts), "output": ["hostid"]})}
    return hosts


def _scope_hostids(api: ZabbixAPI, actions: list[dict], hostgroups: list[dict]) -> list[str] | None:
    """Hosts that can match at least one of the actions, or None when some action is not limited by hosts.

    An action is limited when its filter requires (AND) a host group or host to be equal to given values:
    evaltype "and/or" with all conditions of that type using "=", or evaltype "and" with any such condition.
    The union of the required hosts is returned — a superset, so nothing that can match is lost."""
    by_name = {g["name"]: g["groupid"] for g in hostgroups}
    names = {g["groupid"]: g["name"] for g in hostgroups}

    def nested(gid: str) -> set[str]:
        prefix = names.get(gid, "") + "/"
        return {gid} | {by_name[n] for n in by_name if gid in names and n.startswith(prefix)}

    result: set[str] = set()
    for a in actions:
        flt = a.get("filter") or {}
        evaltype = int(flt.get("evaltype", 0))
        conds = flt.get("conditions") or []
        by_type: dict[int, list[dict]] = {}
        for c in conds:
            by_type.setdefault(int(c["conditiontype"]), []).append(c)
        groups: set[str] = set()
        hosts: set[str] = set()
        limited = False
        for ctype in (C.COND_HOST_GROUP, C.COND_HOST):
            cs = by_type.get(ctype, [])
            eq = [c for c in cs if int(c["operator"]) == C.OP_EQUAL]
            usable = (evaltype == C.EVALTYPE_AND_OR and cs and len(eq) == len(cs)) or (
                evaltype == C.EVALTYPE_AND and eq)
            if not usable:
                continue
            limited = True
            for c in eq:
                if ctype == C.COND_HOST_GROUP:
                    groups |= nested(str(c["value"]))
                else:
                    hosts.add(str(c["value"]))
        if not limited:
            return None
        if groups:
            hosts |= {h["hostid"] for h in api.call("host.get", {"output": ["hostid"], "groupids": sorted(groups)})}
        result |= hosts
    return sorted(result, key=int)


def _macro_value(m: dict) -> str | None:
    # secret (1) and vault (2) macros are not readable through the API
    return m.get("value") if str(m.get("type", "0")) == "0" else None


def _token_user(api: ZabbixAPI) -> dict[str, Any] | None:
    """Who owns the credentials; used to warn when the audit runs without Super admin rights."""
    key = "token" if api.at_least(6, 4) else "sessionid"
    for params in ({key: api.token}, {"sessionid": api.token}):
        try:
            info = api._request("user.checkAuthentication", params, auth=False)
            return {"username": info.get("username"), "type": int(info.get("type", 0))}
        except ZabbixAPIError:
            continue
    return None


def save(raw: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(raw, ensure_ascii=False, indent=1), encoding="utf-8")


def load(path: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("meta", {}).get("format") != SNAPSHOT_FORMAT:
        raise ValueError(f"{path}: unsupported snapshot format")
    return raw
