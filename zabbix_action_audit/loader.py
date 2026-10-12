"""Fetches everything the audit needs in a handful of API calls and normalizes it.

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
from .api import ZabbixAPI, ZabbixAPIError, frontend_base

log = logging.getLogger(__name__)

SNAPSHOT_FORMAT = 1


def fetch_raw(api: ZabbixAPI, *, with_problems: bool = True) -> dict[str, Any]:
    new_groups = api.at_least(6, 2)
    raw: dict[str, Any] = {
        "meta": {
            "format": SNAPSHOT_FORMAT,
            "version": api.version_str or ".".join(map(str, api.version)),
            "frontend": frontend_base(api.url),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    }
    log.info("Zabbix %s", raw["meta"]["version"])
    raw["meta"]["token_user"] = _token_user(api)

    raw["actions"] = api.call("action.get", {
        "output": ["actionid", "name", "status", "esc_period", "pause_suppressed"],
        "filter": {"eventsource": C.EVENTSOURCE_TRIGGERS},
        "selectFilter": "extend",
        "selectOperations": "extend",
        "selectRecoveryOperations": "extend",
        "selectUpdateOperations": "extend",
    })

    raw["hostgroups"] = api.call("hostgroup.get", {"output": ["groupid", "name"]})

    group_key = "hostgroups" if new_groups else "groups"
    hosts = api.call("host.get", {
        "output": ["hostid", "host", "name", "status"],
        "selectHostGroups" if new_groups else "selectGroups": ["groupid"],
        "selectParentTemplates": ["templateid"],
        "selectTags": ["tag", "value"],
        "selectInheritedTags": ["tag", "value"],
    })
    raw["hosts"] = [{
        "hostid": h["hostid"], "host": h["host"], "name": h.get("name", ""), "status": h["status"],
        "groupids": [g["groupid"] for g in h.get(group_key, [])],
        "templateids": [t["templateid"] for t in h.get("parentTemplates", [])],
        "tags": h.get("tags", []), "inheritedTags": h.get("inheritedTags", []),
    } for h in hosts]

    templates = api.call("template.get", {
        "output": ["templateid", "host", "name"],
        "selectParentTemplates": ["templateid"],
        "selectTags": ["tag", "value"],
    })
    raw["templates"] = [{
        "templateid": t["templateid"], "host": t["host"], "name": t.get("name", ""),
        "parent_templateids": [p["templateid"] for p in t.get("parentTemplates", [])],
        "tags": t.get("tags", []),
    } for t in templates]

    triggers = api.call("trigger.get", {
        "output": ["triggerid", "description", "event_name", "priority", "status", "templateid"],
        "templated": False,
        "selectHosts": ["hostid"],
        "selectTags": ["tag", "value"],
    })
    raw["triggers"] = [{
        "triggerid": t["triggerid"], "description": t["description"], "event_name": t.get("event_name", ""),
        "priority": t["priority"], "status": t["status"], "templateid": t.get("templateid", "0"),
        "hostids": [h["hostid"] for h in t.get("hosts", [])], "tags": t.get("tags", []),
    } for t in triggers]

    ttriggers = api.call("trigger.get", {
        "output": ["triggerid", "templateid"], "templated": True, "selectHosts": ["hostid"],
    })
    raw["template_triggers"] = [{
        "triggerid": t["triggerid"], "templateid": t.get("templateid", "0"),
        "hostids": [h["hostid"] for h in t.get("hosts", [])],
    } for t in ttriggers]

    if with_problems:
        raw["problems"] = api.call("problem.get", {
            "output": ["eventid", "objectid", "name", "severity", "clock", "suppressed", "acknowledged"],
            "source": 0, "object": 0, "selectTags": ["tag", "value"],
        })

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
    hmacros = api.call("usermacro.get", {"output": ["hostid", "macro", "value", "type"]})
    raw["macros"] = {
        "global": {m["macro"]: _macro_value(m) for m in gmacros},
        "host": [{"hostid": m["hostid"], "macro": m["macro"], "value": _macro_value(m)} for m in hmacros],
    }
    return raw


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
