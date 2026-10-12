"""Creates (and removes) a self-contained set of zaa-test-* objects on a live Zabbix 6.0 – 7.x."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from zabbix_action_audit import constants as C
from zabbix_action_audit.api import ZabbixAPI, ZabbixAPIError

PASSWORD = "Zaa!Test#2026-pass"
R, D = C.PERM_READ, C.PERM_DENY


@dataclass
class Scenario:
    api: ZabbixAPI
    prefix: str = field(default_factory=lambda: f"zaa-test-{uuid.uuid4().hex[:6]}")
    ids: dict[str, str] = field(default_factory=dict)
    created: list[tuple[str, list[str]]] = field(default_factory=list)  # (delete method, ids)

    # -- helpers ----------------------------------------------------------
    def _create(self, method: str, params: dict, key: str, id_field: str) -> str:
        obj, _ = method.split(".")
        res = self.api.call(method, params)
        new_id = res[id_field][0]
        self.created.append((f"{obj}.delete", [new_id]))
        self.ids[key] = new_id
        return new_id

    def name(self, suffix: str) -> str:
        return f"{self.prefix}-{suffix}"

    @property
    def new_api(self) -> bool:
        return self.api.at_least(6, 2)

    # -- build ------------------------------------------------------------
    def build(self) -> "Scenario":
        try:
            self._build()
        except Exception:
            self.cleanup()
            raise
        return self

    def _build(self) -> None:
        a = self.api
        hg = lambda key, name: self._create("hostgroup.create", {"name": name}, key, "groupids")  # noqa: E731
        root = hg("g_root", f"{self.prefix}/root")
        child = hg("g_child", f"{self.prefix}/root/child")
        deny = hg("g_deny", f"{self.prefix}/deny")
        other = hg("g_other", f"{self.prefix}/other")
        if self.new_api:
            tgroup = self._create("templategroup.create", {"name": f"{self.prefix}/templates"}, "tg", "groupids")
        else:
            tgroup = hg("tg", f"{self.prefix}/templates")

        t_parent = self._create("template.create", {
            "host": self.name("T-parent"), "groups": [{"groupid": tgroup}], "tags": [{"tag": "class", "value": "tpl"}],
        }, "t_parent", "templateids")
        t_child = self._create("template.create", {
            "host": self.name("T-child"), "groups": [{"groupid": tgroup}], "templates": [{"templateid": t_parent}],
        }, "t_child", "templateids")
        a.call("item.create", {"hostid": t_parent, "name": "trap", "key_": "zaa.tpl", "type": 2, "value_type": 3})
        self._create("trigger.create", {
            "description": "Tpl problem on {HOST.NAME}", "priority": 2,
            "expression": self.never(self.name("T-parent"), "zaa.tpl"),
        }, "tt_parent", "triggerids")
        self.created.pop()  # template triggers go away with the template

        def host(key: str, groups: list[str], tags=(), templates=()) -> str:
            hid = self._create("host.create", {
                "host": self.name(key), "groups": [{"groupid": g} for g in groups],
                "tags": [{"tag": t, "value": v} for t, v in tags],
                "templates": [{"templateid": t} for t in templates],
            }, key, "hostids")
            a.call("item.create", {"hostid": hid, "name": "trap", "key_": "zaa.trap", "type": 2, "value_type": 3})
            return hid

        host("h_root", [root], tags=[("env", "prod")], templates=[t_child])
        host("h_child", [child])
        host("h_deny", [root, deny])
        host("h_other", [other], tags=[("env", "dev")])

        def trigger(key: str, hostkey: str, description: str, priority: int, tags=()) -> str:
            tid = self._create("trigger.create", {
                "description": description, "priority": priority, "expression": self.never(self.name(hostkey)),
                "tags": [{"tag": t, "value": v} for t, v in tags],
            }, key, "triggerids")
            self.created.pop()  # deleted together with the host
            return tid

        trigger("tr_root_high", "h_root", "High load on {HOST.NAME}", 4, [("svc", "db")])
        trigger("tr_child_avg", "h_child", "Average child problem", 3)
        trigger("tr_deny_disaster", "h_deny", "Disaster on denied host", 5)
        trigger("tr_other_info", "h_other", "Info on other", 1, [("svc", "web")])
        inherited = a.call("trigger.get", {"hostids": [self.ids["h_root"]], "output": ["triggerid", "templateid"],
                                           "filter": {"description": "Tpl problem on {HOST.NAME}"}})
        self.ids["tr_tpl"] = inherited[0]["triggerid"]

        smtp = {"type": 0, "smtp_server": "127.0.0.1", "smtp_helo": "zaa", "smtp_email": "zaa@example.com"}
        self._create("mediatype.create", {**smtp, "name": self.name("mt-on"), "status": 0, "message_templates": [
            {"eventsource": 0, "recovery": 0, "subject": "P {EVENT.NAME}", "message": "{EVENT.NAME}"}]},
            "mt_on", "mediatypeids")
        self._create("mediatype.create", {**smtp, "name": self.name("mt-off"), "status": 1}, "mt_off", "mediatypeids")

        rights_key = "hostgroup_rights" if self.new_api else "rights"

        def ug(key: str, rights: dict[str, int] | None = None, *, status: int = 0, tag_filters=()) -> str:
            return self._create("usergroup.create", {
                "name": self.name(key), "users_status": status,
                rights_key: [{"id": g, "permission": p} for g, p in (rights or {}).items()],
                "tag_filters": [{"groupid": g, "tag": t, "value": v} for g, t, v in tag_filters],
            }, key, "usrgrpids")

        ug("ug_read", {root: R, child: R})
        ug("ug_deny", {deny: D})
        ug("ug_tag", {root: R}, tag_filters=[(root, "svc", "db")])
        ug("ug_disabled", {root: R}, status=1)
        ug("ug_norights")
        ug("ug_empty")

        roleid = a.call("role.get", {"output": ["roleid"], "filter": {"type": 1}, "sortfield": "roleid"})[0]["roleid"]
        mt_on, mt_off = self.ids["mt_on"], self.ids["mt_off"]

        def media(mtid: str, *, severity: int = 63, active: int = 0) -> dict:
            return {"mediatypeid": mtid, "sendto": ["zaa@example.com"], "active": active, "severity": severity,
                    "period": "1-7,00:00-24:00"}

        def user(key: str, groups: list[str], medias=()) -> str:
            return self._create("user.create", {
                "username": self.name(key), "passwd": PASSWORD, "roleid": roleid,
                "usrgrps": [{"usrgrpid": self.ids[g]} for g in groups], "medias": list(medias),
            }, key, "userids")

        user("u_ok", ["ug_read"], [media(mt_on)])
        user("u_sev", ["ug_read"], [media(mt_on, severity=0b110000)])
        user("u_mediaoff", ["ug_read"], [media(mt_on, active=1)])
        user("u_mtoff", ["ug_read"], [media(mt_off)])
        user("u_nomedia", ["ug_read"])
        user("u_deny", ["ug_read", "ug_deny"], [media(mt_on)])
        user("u_tag", ["ug_tag"], [media(mt_on)])
        user("u_disabled", ["ug_disabled"], [media(mt_on)])
        user("u_norights", ["ug_norights"], [media(mt_on)])

        def send(*, users=(), groups=(), mediatypeid: str = mt_on, **extra) -> dict:
            return {"operationtype": 0, "opmessage": {"default_msg": 1, "mediatypeid": mediatypeid},
                    "opmessage_usr": [{"userid": self.ids[u]} for u in users],
                    "opmessage_grp": [{"usrgrpid": self.ids[g]} for g in groups], **extra}

        def action(key: str, conditions: list[dict], operations: list[dict], *, evaltype: int = 0,
                   formula: str = "", recovery: list[dict] | None = None) -> str:
            flt: dict = {"evaltype": evaltype, "conditions": conditions}
            if formula:
                flt["formula"] = formula
            return self._create("action.create", {
                "name": self.name(key), "eventsource": 0, "status": 1, "esc_period": "1h", "filter": flt,
                "operations": operations, "recovery_operations": recovery or [],
            }, key, "actionids")

        everyone = ["u_ok", "u_sev", "u_mediaoff", "u_mtoff", "u_nomedia", "u_deny", "u_tag", "u_disabled",
                    "u_norights"]
        action("a_main", [{"conditiontype": C.COND_HOST_GROUP, "operator": C.OP_EQUAL, "value": root}],
               [send(users=everyone, esc_step_from=1, esc_step_to=1)],
               recovery=[send(users=["u_ok"])])
        action("a_mtoff", [{"conditiontype": C.COND_HOST, "operator": C.OP_EQUAL, "value": self.ids["h_other"]}],
               [send(groups=["ug_read"], mediatypeid=mt_off, esc_step_from=1, esc_step_to=1)])
        action("a_formula", [
            {"conditiontype": C.COND_TEMPLATE, "operator": C.OP_EQUAL, "value": t_parent, "formulaid": "A"},
            {"conditiontype": C.COND_SEVERITY, "operator": C.OP_MORE_EQUAL, "value": "4", "formulaid": "B"},
            {"conditiontype": C.COND_EVENT_TAG_VALUE, "operator": C.OP_EQUAL, "value2": "svc", "value": "db",
             "formulaid": "C"},
        ], [send(users=["u_ok"], esc_step_from=1, esc_step_to=1)], evaltype=3, formula="A or (B and C)")
        action("a_nothing", [{"conditiontype": C.COND_HOST_GROUP, "operator": C.OP_EQUAL, "value": other},
                             {"conditiontype": C.COND_EVENT_NAME, "operator": C.OP_LIKE, "value": "zzz-no-such"}],
               [send(groups=["ug_empty"], esc_step_from=1, esc_step_to=1)])

    # -- problems -----------------------------------------------------------
    @staticmethod
    def never(host: str, key: str = "zaa.trap") -> str:
        return f"last(/{host}/{key})=-424242"

    @staticmethod
    def firing(host: str, key: str = "zaa.trap") -> str:
        return f"nodata(/{host}/{key},30s)=1"

    def trigger_keys(self) -> list[str]:
        return ["tr_root_high", "tr_child_avg", "tr_deny_disaster", "tr_other_info"]

    def fire(self, timeout: float = 300) -> list[dict]:
        """Switch triggers to an expression that fires without data and wait for the problems."""
        hosts = {"tr_root_high": "h_root", "tr_child_avg": "h_child", "tr_deny_disaster": "h_deny",
                 "tr_other_info": "h_other"}
        for key, hostkey in hosts.items():
            self.api.call("trigger.update", {"triggerid": self.ids[key], "expression": self.firing(self.name(hostkey))})
        self.api.call("trigger.update", {"triggerid": self.ids["tt_parent"],
                                         "expression": self.firing(self.name("T-parent"), "zaa.tpl")})
        wanted = {self.ids[k] for k in [*hosts, "tr_tpl"]}
        deadline = time.time() + timeout
        while time.time() < deadline:
            problems = self.api.call("problem.get", {"objectids": list(wanted), "output": ["eventid", "objectid"]})
            if {p["objectid"] for p in problems} == wanted:
                return problems
            time.sleep(5)
        raise TimeoutError("problems did not appear in time")

    # -- cleanup --------------------------------------------------------------
    def cleanup(self) -> None:
        order = ["action", "user", "usergroup", "mediatype", "host", "template", "hostgroup", "templategroup"]
        for obj in order:
            for method, ids in [c for c in self.created if c[0].split(".")[0] == obj][::-1]:
                try:
                    self.api.call(method, ids)
                except ZabbixAPIError as e:
                    print(f"cleanup {method} {ids}: {e}")
        self.created.clear()


def leftover_cleanup(api: ZabbixAPI) -> None:
    """Remove objects left by an interrupted run."""
    for obj, id_field, name_field in [("action", "actionid", "name"), ("user", "userid", "username"),
                                      ("usergroup", "usrgrpid", "name"), ("mediatype", "mediatypeid", "name"),
                                      ("host", "hostid", "host"), ("template", "templateid", "host"),
                                      ("hostgroup", "groupid", "name"), ("templategroup", "groupid", "name")]:
        if obj == "templategroup" and not api.at_least(6, 2):
            continue
        params = {"output": [id_field], "search": {name_field: "zaa-test-"}, "startSearch": True}
        if obj == "action":
            params["filter"] = {"eventsource": 0}
        ids = [o[id_field] for o in api.call(f"{obj}.get", params)]
        if ids:
            api.call(f"{obj}.delete", ids)
