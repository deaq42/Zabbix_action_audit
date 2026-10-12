"""Command line entry point. Exit codes: 0 — no FAIL, 1 — FAIL found, 2 — runtime error."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from . import config, loader
from .api import ZabbixAPI
from .auditor import Auditor
from .conditions import MODE_ACTIVE, MODE_POTENTIAL
from .model import Snapshot
from .report import RENDERERS

log = logging.getLogger("zabbix_action_audit")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zabbix-action-audit",
                                description="Аудит действий триггеров Zabbix (6.0 LTS – 7.x)")
    src = p.add_argument_group("источник данных")
    src.add_argument("--secrets", default="secrets.txt", help="файл с URL и токеном (по умолчанию secrets.txt)")
    src.add_argument("--url", help="URL фронтенда Zabbix или api_jsonrpc.php")
    src.add_argument("--token", help="API-токен (лучше через ZABBIX_TOKEN или secrets.txt)")
    src.add_argument("--no-verify-ssl", action="store_true", help="не проверять TLS-сертификат")
    src.add_argument("--timeout", type=float, default=120, help="таймаут запроса к API, с")
    src.add_argument("--dump-snapshot", metavar="FILE", help="сохранить выгрузку API в файл")
    src.add_argument("--from-snapshot", metavar="FILE", help="аудит по ранее сохранённой выгрузке, без API")

    au = p.add_argument_group("аудит")
    au.add_argument("--mode", choices=["potential", "active", "both"], default="both",
                    help="potential — все триггеры, active — текущие проблемы, both — оба (по умолчанию)")
    au.add_argument("--action", action="append", metavar="ID|NAME", help="проверить только эти действия (повторяемый)")
    au.add_argument("--skip-disabled", action="store_true", help="не включать отключённые действия")
    au.add_argument("--uncovered", action="store_true",
                    help="перечислить триггеры/проблемы, не подпадающие ни под одно действие с отправкой")
    au.add_argument("--tz", help="часовой пояс сервера Zabbix для периодов времени (по умолчанию — локальный)")

    out = p.add_argument_group("отчёт")
    out.add_argument("--format", choices=sorted(RENDERERS), default=None,
                     help="text, json или html (по умолчанию html при --output *.html, иначе text)")
    out.add_argument("-o", "--output", help="файл отчёта (по умолчанию stdout)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING - 10 * min(args.verbose, 2), format="%(levelname)s %(message)s",
                        stream=sys.stderr)
    try:
        return run(args)
    except KeyboardInterrupt:
        return 2
    except Exception as e:  # noqa: BLE001 - CLI boundary
        log.debug("error", exc_info=True)
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2


def run(args: argparse.Namespace) -> int:
    modes = [MODE_POTENTIAL, MODE_ACTIVE] if args.mode == "both" else [args.mode]
    if args.from_snapshot:
        raw = loader.load(args.from_snapshot)
    else:
        settings = config.resolve(args.url, args.token, args.secrets)
        api = ZabbixAPI(settings.url, settings.token, verify=not args.no_verify_ssl, timeout=args.timeout)
        raw = loader.fetch_raw(api, with_problems=MODE_ACTIVE in modes)
        user = raw["meta"].get("token_user")
        if user and user.get("type") != 3:
            log.warning("Учётная запись %s не Super admin — часть объектов может быть не видна", user.get("username"))
    if args.dump_snapshot:
        loader.save(raw, args.dump_snapshot)
        log.info("Выгрузка сохранена в %s", args.dump_snapshot)

    tz = ZoneInfo(args.tz) if args.tz else datetime.now().astimezone().tzinfo
    result = Auditor(Snapshot(raw), tz=tz).run(modes, action_filter=args.action, skip_disabled=args.skip_disabled,
                                               uncovered=args.uncovered)
    if args.action and not result.actions:
        raise ValueError("Не найдено действий по фильтру --action: " + ", ".join(args.action))

    fmt = args.format or ("html" if args.output and args.output.endswith(".html") else
                          "json" if args.output and args.output.endswith(".json") else "text")
    text = RENDERERS[fmt](result)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Отчёт: {args.output}  (FAIL={result.count('FAIL')}, WARN={result.count('WARN')})", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 1 if result.count("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
