"""Builders for normalized raw snapshots used by unit tests."""

from __future__ import annotations

import copy
from typing import Any


class RawBuilder:
    def __init__(self) -> None:
        self.raw: dict[str, Any] = {
            "meta": {"format": 1, "version": "7.4.0", "frontend": "http://zbx/"},
            "actions": [], "hostgroups": [], "hosts": [], "templates": [], "triggers": [],
            "template_triggers": [], "problems": [], "users": [], "usergroups": [], "mediatypes": [],
            "macros": {"global": {}, "host": []},
        }
        self._id = 1000

    def _next(self) -> str:
        self._id += 1
        return str(self._id)

    def group(self, name: str) -> str:
        gid = self._next()
        self.raw["hostgroups"].append({"groupid": gid, "name": name})
        return gid

    def template(self, name: str, parents: list[str] | None = None, tags: list[tuple[str, str]] | None = None) -> str:
        tid = self._next()
        self.raw["templates"].append({"templateid": tid, "host": name, "name": name,
                                      "parent_templateids": parents or [],
                                      "tags": [{"tag": t, "value": v} for t, v in tags or []]})
        return tid

    def host(self, name: str, groups: list[str], *, templates: list[str] | None = None, enabled: bool = True,
             tags: list[tuple[str, str]] | None = None, inherited: list[tuple[str, str]] | None = None) -> str:
        hid = self._next()
        self.raw["hosts"].append({
            "hostid": hid, "host": name, "name": name.upper(), "status": "0" if enabled else "1",
            "groupids": groups, "templateids": templates or [],
            "tags": [{"tag": t, "value": v} for t, v in tags or []],
            "inheritedTags": [{"tag": t, "value": v} for t, v in inherited or []],
        })
        return hid

    def template_trigger(self, templateid: str, parent: str = "0") -> str:
        tid = self._next()
        self.raw["template_triggers"].append({"triggerid": tid, "templateid": parent, "hostids": [templateid]})
        return tid

    def trigger(self, hosts: list[str], description: str = "Problem", *, priority: int = 3, event_name: str = "",
                enabled: bool = True, templateid: str = "0", tags: list[tuple[str, str]] | None = None) -> str:
        tid = self._next()
        self.raw["triggers"].append({
            "triggerid": tid, "description": description, "event_name": event_name, "priority": str(priority),
            "status": "0" if enabled else "1", "templateid": templateid, "hostids": hosts,
            "tags": [{"tag": t, "value": v} for t, v in tags or []],
        })
        return tid

    def problem(self, triggerid: str, name: str = "", *, severity: int = 3, clock: int = 1_700_000_000,
                suppressed: bool = False, tags: list[tuple[str, str]] | None = None) -> str:
        eid = self._next()
        self.raw["problems"].append({
            "eventid": eid, "objectid": triggerid, "name": name, "severity": str(severity), "clock": str(clock),
            "suppressed": "1" if suppressed else "0", "acknowledged": "0",
            "tags": [{"tag": t, "value": v} for t, v in tags or []],
        })
        return eid

    def mediatype(self, name: str = "Mail", *, enabled: bool = True, templates: tuple[int, ...] = (0, 1, 2)) -> str:
        mid = self._next()
        self.raw["mediatypes"].append({
            "mediatypeid": mid, "name": name, "type": "0", "status": "0" if enabled else "1",
            "message_templates": [{"eventsource": "0", "recovery": str(r)} for r in templates],
        })
        return mid

    def user(self, name: str, groups: list[str], *, super_admin: bool = False,
             medias: list[dict[str, Any]] | None = None) -> str:
        uid = self._next()
        self.raw["users"].append({"userid": uid, "username": name, "name": "", "surname": "",
                                  "role_type": "3" if super_admin else "1", "usrgrpids": groups,
                                  "medias": medias or []})
        for g in self.raw["usergroups"]:
            if g["usrgrpid"] in groups:
                g["userids"].append(uid)
        return uid

    @staticmethod
    def media(mediatypeid: str, *, sendto: str = "x@y", active: bool = True, severity: int = 63,
              period: str = "1-7,00:00-24:00") -> dict[str, Any]:
        return {"mediaid": "1", "mediatypeid": mediatypeid, "sendto": sendto, "active": "0" if active else "1",
                "severity": str(severity), "period": period}

    def usergroup(self, name: str, rights: dict[str, int] | None = None, *, enabled: bool = True,
                  tag_filters: list[tuple[str, str, str]] | None = None) -> str:
        gid = self._next()
        self.raw["usergroups"].append({
            "usrgrpid": gid, "name": name, "users_status": "0" if enabled else "1",
            "rights": [{"id": k, "permission": str(v)} for k, v in (rights or {}).items()],
            "tag_filters": [{"groupid": g, "tag": t, "value": v} for g, t, v in tag_filters or []],
            "userids": [],
        })
        return gid

    def action(self, name: str = "Act", conditions: list[tuple] | None = None, *, evaltype: int = 0,
               formula: str = "", enabled: bool = True, operations: list[dict] | None = None,
               recovery: list[dict] | None = None) -> str:
        aid = self._next()
        conds = []
        for i, c in enumerate(conditions or []):
            ctype, op, value, *rest = c
            conds.append({"conditiontype": str(ctype), "operator": str(op), "value": str(value),
                          "value2": rest[0] if rest else "", "formulaid": chr(ord("A") + i)})
        self.raw["actions"].append({
            "actionid": aid, "name": name, "status": "0" if enabled else "1", "esc_period": "1h",
            "pause_suppressed": "0",
            "filter": {"evaltype": str(evaltype), "formula": formula, "conditions": conds},
            "operations": operations or [], "recovery_operations": recovery or [], "update_operations": [],
        })
        return aid

    @staticmethod
    def send(users: list[str] | None = None, groups: list[str] | None = None, mediatypeid: str = "0",
             default_msg: bool = True) -> dict[str, Any]:
        return {"operationid": "1", "operationtype": "0", "esc_step_from": "1", "esc_step_to": "1",
                "opmessage": {"default_msg": "1" if default_msg else "0", "mediatypeid": mediatypeid},
                "opmessage_usr": [{"userid": u} for u in users or []],
                "opmessage_grp": [{"usrgrpid": g} for g in groups or []], "opconditions": []}

    def global_macro(self, macro: str, value: str | None) -> None:
        self.raw["macros"]["global"][macro] = value

    def host_macro(self, hostid: str, macro: str, value: str | None) -> None:
        self.raw["macros"]["host"].append({"hostid": hostid, "macro": macro, "value": value})

    def build(self) -> dict[str, Any]:
        return copy.deepcopy(self.raw)
