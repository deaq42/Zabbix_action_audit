from __future__ import annotations

import json
from dataclasses import asdict

from ..auditor import AuditResult


def render_json(result: AuditResult) -> str:
    data = asdict(result)
    data["summary"] = {lvl: result.count(lvl) for lvl in ("FAIL", "WARN", "INFO", "OK")}
    return json.dumps(data, ensure_ascii=False, indent=1)
