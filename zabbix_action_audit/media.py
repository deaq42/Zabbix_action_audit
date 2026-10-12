"""Can a user receive a message of a given severity via the operation's media type?"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, tzinfo

from . import constants as C
from .macros import MacroResolver
from .model import Media, Snapshot, User
from .period import parse_period

USER_NO_MEDIA = "USER_NO_MEDIA"
MEDIA_DISABLED = "MEDIA_DISABLED"
MEDIATYPE_DISABLED = "MEDIATYPE_DISABLED"
MEDIATYPE_MISSING = "MEDIATYPE_MISSING"
MEDIA_SEVERITY_EXCLUDED = "MEDIA_SEVERITY_EXCLUDED"
MEDIA_EMPTY_SENDTO = "MEDIA_EMPTY_SENDTO"
MEDIATYPE_NO_MESSAGE_TEMPLATE = "MEDIATYPE_NO_MESSAGE_TEMPLATE"
MEDIA_PERIOD_LIMITED = "MEDIA_PERIOD_LIMITED"
MEDIA_PERIOD_EXCLUDED = "MEDIA_PERIOD_EXCLUDED"

FAIL_CODES = {USER_NO_MEDIA, MEDIA_DISABLED, MEDIATYPE_DISABLED, MEDIATYPE_MISSING, MEDIA_SEVERITY_EXCLUDED}
WARN_CODES = {MEDIA_EMPTY_SENDTO, MEDIATYPE_NO_MESSAGE_TEMPLATE, MEDIA_PERIOD_EXCLUDED}


@dataclass
class MediaIssue:
    code: str
    detail: str


@dataclass
class MediaVerdict:
    media: Media | None
    mediatype_name: str
    issues: list[MediaIssue] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(i.code in FAIL_CODES for i in self.issues)


@dataclass
class MediaResult:
    """Outcome for one user: delivered if at least one media passes all FAIL checks."""

    verdicts: list[MediaVerdict]

    @property
    def ok(self) -> bool:
        return any(not v.failed for v in self.verdicts)

    @property
    def issues(self) -> list[MediaIssue]:
        """When delivery works: notes of the working media; otherwise every reason of every media."""
        if self.ok:
            return [i for v in self.verdicts if not v.failed for i in v.issues]
        return [i for v in self.verdicts for i in v.issues]


class MediaChecker:
    def __init__(self, snap: Snapshot, tz: tzinfo | None = None):
        self.snap = snap
        self.tz = tz
        self.macros = MacroResolver(snap)

    def mediatype_name(self, mediatypeid: str) -> str:
        if mediatypeid == "0":
            return "все"
        mt = self.snap.mediatypes.get(mediatypeid)
        return mt.name if mt else f"#{mediatypeid}"

    def check(self, user: User, mediatypeid: str, severity: int, *, opkind: str = C.OPKIND_PROBLEM,
              default_msg: bool = True, clock: int | None = None) -> MediaResult:
        medias = [m for m in user.medias if mediatypeid == "0" or m.mediatypeid == mediatypeid]
        if not medias:
            what = "ни одного медиа" if mediatypeid == "0" else f"медиа типа «{self.mediatype_name(mediatypeid)}»"
            return MediaResult([MediaVerdict(None, self.mediatype_name(mediatypeid),
                                             [MediaIssue(USER_NO_MEDIA, f"у пользователя нет {what}")])])
        return MediaResult([self._one(m, severity, opkind, default_msg, clock) for m in medias])

    def _one(self, m: Media, severity: int, opkind: str, default_msg: bool, clock: int | None) -> MediaVerdict:
        mt = self.snap.mediatypes.get(m.mediatypeid)
        v = MediaVerdict(m, mt.name if mt else f"#{m.mediatypeid}")
        if mt is None:
            v.issues.append(MediaIssue(MEDIATYPE_MISSING, "тип медиа не найден"))
            return v
        if not mt.enabled:
            v.issues.append(MediaIssue(MEDIATYPE_DISABLED, f"тип медиа «{mt.name}» отключён"))
        if not m.active:
            v.issues.append(MediaIssue(MEDIA_DISABLED, f"медиа «{mt.name}» пользователя отключено"))
        if not m.allows(severity):
            allowed = [C.SEVERITY_SHORT[s] for s in range(6) if m.allows(s)] or ["нет"]
            v.issues.append(MediaIssue(MEDIA_SEVERITY_EXCLUDED,
                                       f"«{mt.name}»: важность {C.SEVERITY_NAMES[severity]} не включена "
                                       f"(разрешены: {', '.join(allowed)})"))
        if not m.sendto.strip():
            v.issues.append(MediaIssue(MEDIA_EMPTY_SENDTO, f"«{mt.name}»: пустой адрес получателя"))
        if default_msg and (C.EVENTSOURCE_TRIGGERS, C.OPKIND_TEMPLATE_RECOVERY[opkind]) not in mt.message_templates:
            v.issues.append(MediaIssue(MEDIATYPE_NO_MESSAGE_TEMPLATE,
                                       f"«{mt.name}»: нет шаблона сообщения для «{C.OPKIND_NAMES[opkind]}»"))
        v.issues += self._period(m, mt.name, clock)
        return v

    def _period(self, m: Media, mt_name: str, clock: int | None) -> list[MediaIssue]:
        text = self.macros.expand(m.period, [])
        period = parse_period(text.text) if text.exact else None
        if period is None:
            return [MediaIssue(MEDIA_PERIOD_LIMITED, f"«{mt_name}»: не удалось разобрать период «{m.period}»")]
        if period.always:
            return []
        if clock is not None and not period.contains(datetime.fromtimestamp(clock, self.tz)):
            return [MediaIssue(MEDIA_PERIOD_EXCLUDED,
                               f"«{mt_name}»: проблема возникла вне периода активности «{m.period}»")]
        return [MediaIssue(MEDIA_PERIOD_LIMITED, f"«{mt_name}»: активно только в период «{m.period}»")]
