"""Best-effort macro expansion for event names and tags of triggers (potential mode).

The result keeps unresolved macros as holes, so callers can tell a definite answer from
a guess: ``Expanded.contains("x")`` is True/False when certain and None when it depends
on a value only known at event time (e.g. ``{ITEM.LASTVALUE}``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .model import Snapshot

_USER_MACRO = re.compile(r'^\{\$([A-Z0-9_.]+)(?::(.*))?\}$', re.S)
_HOST_MACRO = re.compile(r"^\{(HOST\.HOST|HOST\.NAME|HOSTNAME)(\d?)\}$")


@dataclass(frozen=True)
class Expanded:
    segments: tuple[str | None, ...]  # None = unresolved macro

    @property
    def exact(self) -> bool:
        return None not in self.segments

    @property
    def text(self) -> str:
        """Display form; unresolved macros are shown as «?»."""
        return "".join("«?»" if s is None else s for s in self.segments)

    def contains(self, needle: str) -> bool | None:
        if self.exact:
            return needle in self.text
        if any(s is not None and needle in s for s in self.segments):
            return True
        return None

    def equals(self, value: str) -> bool | None:
        if self.exact:
            return self.text == value
        pattern = "".join(".*" if s is None else re.escape(s) for s in self.segments)
        return None if re.fullmatch(pattern, value, re.S) else False


def literal(text: str) -> Expanded:
    return Expanded((text,))


def tokenize(text: str) -> list[tuple[bool, str]]:
    """Split into (is_macro, chunk); macros are balanced {...} groups (handles {{ITEM.VALUE}.regsub(...)})."""
    out: list[tuple[bool, str]] = []
    buf, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "{":
            depth, j = 0, i
            while j < n:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < n:
                if buf:
                    out.append((False, "".join(buf)))
                    buf = []
                out.append((True, text[i:j + 1]))
                i = j + 1
                continue
        buf.append(text[i])
        i += 1
    if buf:
        out.append((False, "".join(buf)))
    return out


def _parse_user_macro(token: str) -> tuple[str, str | None, bool] | None:
    """{$NAME:"ctx"} -> (NAME, ctx, is_regex)"""
    m = _USER_MACRO.match(token)
    if not m:
        return None
    name, ctx = m.group(1), m.group(2)
    if ctx is None:
        return name, None, False
    is_regex = ctx.startswith("regex:")
    if is_regex:
        ctx = ctx[len("regex:"):]
    if len(ctx) >= 2 and ctx[0] == '"' and ctx[-1] == '"':
        ctx = ctx[1:-1].replace('\\"', '"')
    return name, ctx, is_regex


class MacroResolver:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self._levels_cache: dict[str, list[dict[tuple[str, str | None, bool], str | None]]] = {}
        self._global = self._index(snap.global_macros)

    @staticmethod
    def _index(macros: dict[str, str | None]) -> dict[tuple[str, str | None, bool], str | None]:
        out = {}
        for macro, value in macros.items():
            parsed = _parse_user_macro(macro)
            if parsed:
                out[parsed] = value
        return out

    def _levels(self, hostid: str) -> list[dict]:
        """Macro tables in resolution order: host, its templates level by level (lowest id first), global."""
        if hostid in self._levels_cache:
            return self._levels_cache[hostid]
        levels = [self._index(self.snap.host_macros.get(hostid, {}))]
        host = self.snap.hosts.get(hostid)
        frontier = sorted(host.templateids if host else [], key=int)
        seen: set[str] = set()
        while frontier:
            nxt: list[str] = []
            for tid in frontier:
                if tid in seen:
                    continue
                seen.add(tid)
                levels.append(self._index(self.snap.host_macros.get(tid, {})))
                tpl = self.snap.templates.get(tid)
                if tpl:
                    nxt.extend(tpl.parent_templateids)
            frontier = sorted(set(nxt) - seen, key=int)
        levels.append(self._global)
        self._levels_cache[hostid] = levels
        return levels

    def user_macro(self, token: str, hostid: str | None) -> str | None:
        parsed = _parse_user_macro(token)
        if not parsed:
            return None
        name, ctx, is_regex = parsed
        levels = self._levels(hostid) if hostid else [self._global]
        if ctx is not None and not is_regex:
            for lvl in levels:  # 1. exact context
                if (name, ctx, False) in lvl:
                    return lvl[(name, ctx, False)]
            for lvl in levels:  # 2. regex context
                for (n, c, rx), value in lvl.items():
                    if n == name and rx and c is not None:
                        try:
                            if re.search(c, ctx):
                                return value
                        except re.error:
                            continue
        for lvl in levels:  # 3. macro without context
            if (name, None, False) in lvl:
                return lvl[(name, None, False)]
        return None

    def expand(self, text: str, hostids: list[str]) -> Expanded:
        segments: list[str | None] = []
        for is_macro, chunk in tokenize(text):
            value: str | None = chunk if not is_macro else None
            if is_macro:
                if chunk.startswith("{$"):
                    value = self.user_macro(chunk, hostids[0] if len(hostids) == 1 else None)
                    if value is None and len(hostids) > 1:
                        values = {self.user_macro(chunk, h) for h in hostids}
                        value = values.pop() if len(values) == 1 else None
                else:
                    m = _HOST_MACRO.match(chunk)
                    # {HOST.*N} follows the order of hosts in the trigger expression, which the API
                    # does not expose, so multi-host triggers stay unresolved.
                    if m and len(hostids) == 1 and m.group(2) in ("", "1"):
                        host = self.snap.hosts.get(hostids[0])
                        if host:
                            value = host.name if m.group(1) == "HOST.NAME" else host.host
            if value is not None and segments and segments[-1] is not None:
                segments[-1] += value
            else:
                segments.append(value)
        return Expanded(tuple(segments) or ("",))
