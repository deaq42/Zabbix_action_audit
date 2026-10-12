from __future__ import annotations

from ..auditor import AuditResult

MODE_TITLES = {"potential": "Потенциальные (триггеры)", "active": "Текущие проблемы"}


def render_text(result: AuditResult, *, max_items: int = 5) -> str:
    out: list[str] = []
    meta = result.meta
    out.append(f"Аудит действий Zabbix {meta.get('version', '')} — {meta.get('frontend', '')} — {meta.get('audited', '')}")
    out.append("Итого (включённые действия): " + ", ".join(
        f"{lvl}={result.count(lvl)}" for lvl in ("FAIL", "WARN", "INFO", "OK")))
    for a in result.actions:
        out.append("")
        out.append(f"[{a.worst}] Действие «{a.name}» (id {a.actionid}){'' if a.enabled else ' — ОТКЛЮЧЕНО'}")
        out.append(f"  Условия ({a.evaltype}): " + ("; ".join(a.conditions) or "нет — подходят все проблемы"))
        for f in a.findings:
            out.append(f"  {f.level}: {f.message}")
        for mode, m in a.modes.items():
            cands = result.candidates[mode]
            out.append(f"  {MODE_TITLES[mode]}: подходит {len(m.matched)}, не определено {len(m.undecided)}; "
                       + ", ".join(f"{k}={v}" for k, v in m.counts.items() if v))
            for f in m.findings:
                out.append(f"    {f.level}: {f.message}")
            for op in m.operations:
                out.append(f"    • {op.title} [{op.context}]")
                for f in op.findings:
                    out.append(f"      {f.level}: {f.message}")
                for r in op.recipients:
                    out.append(f"      – {r.label} ({', '.join(r.via)})")
                    for f in r.findings:
                        out.append(f"          {f.level}: {f.message}")
                    for g in r.outcomes:
                        if g.level == "OK":
                            out.append(f"          OK: {len(g.candidates)}")
                            continue
                        names = [cands[k]["name"] for k in g.candidates[:max_items]]
                        more = f" … и ещё {len(g.candidates) - max_items}" if len(g.candidates) > max_items else ""
                        out.append(f"          {g.level} {', '.join(g.codes)}: {len(g.candidates)} — "
                                   + "; ".join(names) + more)
                        for d in g.details[:3]:
                            out.append(f"              {d}")
    for mode, keys in result.uncovered.items():
        out.append("")
        out.append(f"{MODE_TITLES[mode]} без единого действия с отправкой сообщений: {len(keys)}")
        for k in keys[:max_items * 2]:
            c = result.candidates[mode][k]
            out.append(f"  - {c['name']} ({', '.join(c['hosts'])})")
    return "\n".join(out) + "\n"
