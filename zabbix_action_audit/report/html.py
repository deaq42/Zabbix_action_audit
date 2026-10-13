from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import constants as C
from ..auditor import ActionReport, AuditResult
from .text import MODE_TITLES

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)

LEVELS = ("FAIL", "WARN", "INFO", "OK")


class _Lists:
    """Candidate key lists are repeated a lot (every recipient of a broad action gets the same list),
    so the page stores each distinct list once and elements refer to it by index."""

    def __init__(self) -> None:
        self.index: dict[tuple[str, ...], int] = {}
        self.lists: list[list[str]] = []

    def ref(self, keys) -> int:
        t = tuple(keys)
        if t not in self.index:
            self.index[t] = len(self.lists)
            self.lists.append(list(t))
        return self.index[t]

    def undecided(self, und: dict[str, list[str]]) -> str:
        """Undecided notes grouped by text: an action with a time period condition would otherwise repeat
        the same note for every trigger."""
        groups: dict[tuple[str, ...], list[str]] = {}
        for key, notes in und.items():
            groups.setdefault(tuple(notes), []).append(key)
        return json.dumps([[self.ref(keys), list(notes)] for notes, keys in groups.items()],
                          ensure_ascii=False, separators=(",", ":"))


def _page(result: AuditResult, **extra) -> str:
    lists = _Lists()
    summary = {lvl: result.count(lvl) for lvl in LEVELS}
    page = _env.get_template("report.html.j2").render(
        r=result, summary=summary, mode_titles=MODE_TITLES, severities=C.SEVERITY_NAMES, ref=lists.ref,
        und=lists.undecided, **extra,
    )
    # the lists are known only after rendering, so they are injected at the end
    return page.replace("<!--KEY_LISTS-->", json.dumps(lists.lists, separators=(",", ":"))
                        .replace("<", "\\u003c"), 1)


def render_html(result: AuditResult) -> str:
    return _page(result)


def _subset(result: AuditResult, actions: list[ActionReport], uncovered: dict[str, list[str]]) -> AuditResult:
    keys = {m: set(uncovered.get(m, ())) for m in result.modes}
    for a in actions:
        for mode, mr in a.modes.items():
            keys[mode].update(mr.matched, mr.undecided)
    return dataclasses.replace(result, actions=actions, uncovered=uncovered, candidates={
        mode: {k: v for k, v in result.candidates.get(mode, {}).items() if k in keys[mode]} for mode in result.modes})


def _problem_codes(a: ActionReport) -> list[str]:
    codes = {f.code for f in a.findings if f.level in ("FAIL", "WARN")}
    for m in a.modes.values():
        codes |= {f.code for f in m.findings if f.level in ("FAIL", "WARN")}
        for op in m.operations:
            codes |= {f.code for f in op.findings if f.level in ("FAIL", "WARN")}
            for rc in op.recipients:
                codes |= {f.code for f in rc.findings if f.level in ("FAIL", "WARN")}
                codes |= {c for g in rc.outcomes if g.level in ("FAIL", "WARN") for c in g.codes}
    return sorted(codes)


def render_html_split(result: AuditResult) -> dict[str, str]:
    """index.html with a table of actions plus a page per action: each page carries only its own data,
    so a full audit of a large installation opens quickly."""
    files: dict[str, str] = {}
    rows = []
    for a in result.actions:
        name = f"action-{a.actionid}.html"
        sub = _subset(result, [a], {})
        files[name] = _page(sub, single=True, index_link=True)
        rows.append({"action": a, "file": name, "codes": _problem_codes(a),
                     "counts": {lvl: sub.count(lvl, enabled_only=False) for lvl in LEVELS}})
    uncovered_file = None
    if any(result.uncovered.values()):
        uncovered_file = "uncovered.html"
        files[uncovered_file] = _page(_subset(result, [], result.uncovered), index_link=True)
    files["index.html"] = _env.get_template("index.html.j2").render(
        r=result, rows=rows, summary={lvl: result.count(lvl) for lvl in LEVELS}, mode_titles=MODE_TITLES,
        uncovered_file=uncovered_file,
    )
    return files
