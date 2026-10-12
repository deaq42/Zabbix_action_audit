"""Numeric codes of the Zabbix API (identical in 6.0 LTS and 7.x unless noted)."""

from __future__ import annotations

# action.eventsource
EVENTSOURCE_TRIGGERS = 0

# action filter evaltype
EVALTYPE_AND_OR = 0
EVALTYPE_AND = 1
EVALTYPE_OR = 2
EVALTYPE_FORMULA = 3

# action condition types relevant for eventsource=0
COND_HOST_GROUP = 0
COND_HOST = 1
COND_TRIGGER = 2
COND_EVENT_NAME = 3
COND_SEVERITY = 4
COND_TIME_PERIOD = 6
COND_TEMPLATE = 13
COND_SUPPRESSED = 16
COND_EVENT_TAG = 25
COND_EVENT_TAG_VALUE = 26

CONDITION_NAMES = {
    COND_HOST_GROUP: "Группа узлов",
    COND_HOST: "Узел",
    COND_TRIGGER: "Триггер",
    COND_EVENT_NAME: "Имя события",
    COND_SEVERITY: "Важность",
    COND_TIME_PERIOD: "Период времени",
    COND_TEMPLATE: "Шаблон",
    COND_SUPPRESSED: "Проблема подавлена",
    COND_EVENT_TAG: "Тег события",
    COND_EVENT_TAG_VALUE: "Значение тега события",
}

# condition operators
OP_EQUAL = 0
OP_NOT_EQUAL = 1
OP_LIKE = 2
OP_NOT_LIKE = 3
OP_IN = 4
OP_MORE_EQUAL = 5
OP_LESS_EQUAL = 6
OP_NOT_IN = 7
OP_REGEXP = 8
OP_NOT_REGEXP = 9
OP_YES = 10
OP_NO = 11

OPERATOR_NAMES = {
    OP_EQUAL: "=",
    OP_NOT_EQUAL: "≠",
    OP_LIKE: "содержит",
    OP_NOT_LIKE: "не содержит",
    OP_IN: "в",
    OP_MORE_EQUAL: "≥",
    OP_LESS_EQUAL: "≤",
    OP_NOT_IN: "не в",
    OP_REGEXP: "совпадает с",
    OP_NOT_REGEXP: "не совпадает с",
    OP_YES: "да",
    OP_NO: "нет",
}

# operation types
OPTYPE_MESSAGE = 0
OPTYPE_COMMAND = 1
OPTYPE_RECOVERY_MESSAGE = 11  # "notify all involved" in recovery operations
OPTYPE_UPDATE_MESSAGE = 12  # "notify all involved" in update operations

# operation kinds -> media type message template "recovery" field
OPKIND_PROBLEM = "problem"
OPKIND_RECOVERY = "recovery"
OPKIND_UPDATE = "update"
OPKIND_TEMPLATE_RECOVERY = {OPKIND_PROBLEM: 0, OPKIND_RECOVERY: 1, OPKIND_UPDATE: 2}
OPKIND_NAMES = {OPKIND_PROBLEM: "Операции", OPKIND_RECOVERY: "Восстановление", OPKIND_UPDATE: "Обновление"}

SEVERITY_NAMES = ["Не классифицировано", "Информация", "Предупреждение", "Средняя", "Высокая", "Чрезвычайная"]
SEVERITY_SHORT = ["N/C", "Info", "Warn", "Avg", "High", "Disaster"]

# permissions
PERM_DENY = 0
PERM_READ = 2
PERM_READ_WRITE = 3

# role.type
USER_TYPE_SUPER_ADMIN = 3

MEDIATYPE_TYPES = {0: "Email", 1: "Script", 2: "SMS", 4: "Webhook"}
