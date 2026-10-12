from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import constants as C
from ..auditor import AuditResult
from .text import MODE_TITLES

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)


def render_html(result: AuditResult) -> str:
    summary = {lvl: result.count(lvl) for lvl in ("FAIL", "WARN", "INFO", "OK")}
    return _env.get_template("report.html.j2").render(
        r=result, summary=summary, mode_titles=MODE_TITLES, severities=C.SEVERITY_NAMES,
    )
