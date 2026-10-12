from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import constants as C
from ..auditor import AuditResult
from .text import MODE_TITLES

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)


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


def render_html(result: AuditResult) -> str:
    summary = {lvl: result.count(lvl) for lvl in ("FAIL", "WARN", "INFO", "OK")}
    lists = _Lists()
    page = _env.get_template("report.html.j2").render(
        r=result, summary=summary, mode_titles=MODE_TITLES, severities=C.SEVERITY_NAMES, ref=lists.ref,
    )
    # the lists are known only after rendering, so they are injected at the end
    return page.replace("<!--KEY_LISTS-->", json.dumps(lists.lists, separators=(",", ":"))
                        .replace("<", "\\u003c"), 1)
