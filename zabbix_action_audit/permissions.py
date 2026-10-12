"""Effective permissions of a user, computed the way Zabbix server does before sending a notification.

- A user in any user group with ``users_status=1`` is disabled and gets nothing.
- Super admins see everything; tag filters do not apply to them.
- Permission on a host group across the user's groups: Deny wins, otherwise the highest.
- Permission on a host across its host groups: Deny on any group wins, otherwise the highest.
- A trigger requires at least Read on every host of the trigger.
- Tag filters: for a host group granted by a user group with no tag filters on it, all problems
  are visible; otherwise the problem must carry a tag matching one of the filters.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from . import constants as C
from .conditions import Candidate, tri_and, tri_or
from .model import Snapshot, User

ACCESS_OK = "OK"
USER_DISABLED = "USER_DISABLED"
USER_NO_HOST_ACCESS = "USER_NO_HOST_ACCESS"
USER_TAG_FILTER_BLOCKS = "USER_TAG_FILTER_BLOCKS"
ACCESS_UNKNOWN = "USER_TAG_FILTER_UNKNOWN"


@dataclass(frozen=True)
class Access:
    code: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.code == ACCESS_OK


class PermissionResolver:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.group_permission = lru_cache(maxsize=None)(self._group_permission)
        self.host_permission = lru_cache(maxsize=None)(self._host_permission)

    def user(self, userid: str) -> User | None:
        return self.snap.users.get(userid)

    def disabled_by(self, user: User) -> list[str]:
        """Names of the disabled user groups the user belongs to."""
        return [g.name for gid in user.usrgrpids if (g := self.snap.usergroups.get(gid)) and not g.enabled]

    def _group_permission(self, userid: str, groupid: str) -> int | None:
        """None = no permission at all."""
        user = self.snap.users[userid]
        if user.is_super_admin:
            return C.PERM_READ_WRITE
        perms = [g.rights[groupid] for gid in user.usrgrpids
                 if (g := self.snap.usergroups.get(gid)) and groupid in g.rights]
        if not perms:
            return None
        return C.PERM_DENY if C.PERM_DENY in perms else max(perms)

    def _host_permission(self, userid: str, hostid: str) -> int | None:
        host = self.snap.hosts.get(hostid)
        if host is None:
            return None
        perms = [p for g in host.groupids if (p := self.group_permission(userid, g)) is not None]
        if not perms:
            return None
        return C.PERM_DENY if C.PERM_DENY in perms else max(perms)

    def can_read_host(self, userid: str, hostid: str) -> bool:
        return (self.host_permission(userid, hostid) or 0) >= C.PERM_READ

    def can_read_group(self, userid: str, groupid: str) -> bool:
        return (self.group_permission(userid, groupid) or 0) >= C.PERM_READ

    def _tags_visible(self, user: User, cand: Candidate) -> bool | None:
        """Visible if any readable host group of the trigger's hosts passes the tag filters."""
        verdicts: list[bool | None] = []
        for hostid in cand.hostids:
            host = self.snap.hosts.get(hostid)
            for groupid in host.groupids if host else []:
                if not self.can_read_group(user.userid, groupid):
                    continue
                filters = []
                unfiltered = False
                for gid in user.usrgrpids:
                    ug = self.snap.usergroups.get(gid)
                    if not ug or ug.rights.get(groupid, C.PERM_DENY) < C.PERM_READ:
                        continue
                    own = [f for f in ug.tag_filters if f.groupid == groupid]
                    if not own:
                        unfiltered = True
                        break
                    filters += own
                if unfiltered:
                    return True
                for f in filters:
                    if not f.tag:
                        verdicts.append(True)
                        continue
                    verdicts.append(tri_or(
                        tri_and((name.equals(f.tag), value.equals(f.value) if f.value else True))
                        for name, value in cand.tags
                    ))
        return tri_or(verdicts)

    def access(self, userid: str, cand: Candidate) -> Access:
        user = self.snap.users.get(userid)
        if user is None:
            return Access(USER_NO_HOST_ACCESS, "пользователь не найден")
        disabled = self.disabled_by(user)
        if disabled:
            return Access(USER_DISABLED, "состоит в отключённой группе: " + ", ".join(disabled))
        if user.is_super_admin:
            return Access(ACCESS_OK)
        denied = [h for h in cand.hostids if not self.can_read_host(userid, h)]
        if denied:
            return Access(USER_NO_HOST_ACCESS, "нет прав на чтение: " + ", ".join(self.snap.host_label(h) for h in denied))
        visible = self._tags_visible(user, cand)
        if visible is False:
            return Access(USER_TAG_FILTER_BLOCKS, "проблема скрыта tag-фильтрами групп пользователя")
        if visible is None:
            return Access(ACCESS_UNKNOWN, "видимость по tag-фильтрам зависит от нераскрываемых макросов в тегах")
        return Access(ACCESS_OK)
