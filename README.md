# Zabbix Action Audit

Аудит действий триггеров Zabbix (6.0 LTS – 7.4). По каждому действию показывает:

- под какие триггеры (`potential`) и текущие проблемы (`active`) оно попадает;
- дойдёт ли уведомление до каждого получателя, и если нет — почему: отключён пользователь, нет прав на хост,
  проблему скрывают tag-фильтры, нет медиа нужного типа, медиа/тип медиа отключены, важность не включена в медиа и т.д.

Техзадание и архитектура: [docs/TZ.md](docs/TZ.md).

## Запуск

```bash
pip install -e .            # или без установки: python3 -m zabbix_action_audit ...
zabbix-action-audit -o reports/audit.html                 # HTML, оба режима
zabbix-action-audit --mode active --format text           # только текущие проблемы, в консоль
zabbix-action-audit --action "all problems to tg" --uncovered -o audit.html
zabbix-action-audit --dump-snapshot snap.json -o a.html   # сохранить выгрузку API
zabbix-action-audit --from-snapshot snap.json -o a.html   # аудит офлайн по выгрузке
```

Подключение: `secrets.txt` (`Zabbix_url: …`, `Zabbix token: …`), переменные `ZABBIX_URL` / `ZABBIX_TOKEN`
или `--url` / `--token`. Нужен токен Super admin: аудит только читает API.

Коды возврата: `0` — нет FAIL во включённых действиях, `1` — есть FAIL, `2` — ошибка выполнения.

«Не определено» означает, что результат зависит от того, что известно только в момент события: период времени,
подавление, макросы вроде `{ITEM.LASTVALUE}` в имени или тегах. Такие триггеры показаны отдельно.

## Тесты

```bash
python3 -m pytest                       # юнит-тесты, без сети
python3 -m pytest -m integration        # на живых стендах
```

Интеграционные стенды:

- `local` — Zabbix из `secrets.txt`;
- `zbx60` — одноразовый 6.0 LTS: `docker compose -f tests/zabbix60/docker-compose.yml up -d`
  (`down`, чтобы удалить; база в tmpfs).

Выбор стендов: `ZAA_STANDS=local,zbx60`. Тесты создают объекты `zaa-test-*` и удаляют их после себя
(остатки прерванного запуска удаляются при следующем). Тестовые проблемы генерируются только если ни одно
существующее включённое действие стенда не отправит по ним уведомления.
