from __future__ import annotations

from .html import render_html
from .json_ import render_json
from .text import render_text

RENDERERS = {"text": render_text, "json": render_json, "html": render_html}

__all__ = ["RENDERERS", "render_html", "render_json", "render_text"]
