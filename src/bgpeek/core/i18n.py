"""Simple dict-based internationalization for bgpeek templates."""

from __future__ import annotations

TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "site_name": "bgpeek",
        "network_query": "Network Query",
        "location": "Location",
        "select_device": "— select device —",
        "query_type": "Query type",
        "bgp_route": "BGP route",
        "ping": "Ping",
        "traceroute": "Traceroute",
        "target": "Target",
        "run_query": "Run query",
        "abort": "Abort",
        "running": "running…",
        "empty_state": "Run a query to see results",
        "cached": "cached",
        "show_raw": "Show raw output",
        "share": "Share",
        "copied": "Copied!",
        "login": "Login",
        "logout": "Logout",
        "sign_in": "Sign in",
        "username": "Username",
        "password": "Password",
        "history": "History",
        "query_history": "Query History",
        "recent_queries": "Recent queries",
        "time": "Time",
        "device": "Device",
        "runtime": "Runtime",
        "status": "Status",
        "actions": "Actions",
        "view": "View",
        "load_more": "Load more",
        "no_results": "No queries yet",
        "shared_result": "Shared result",
        "created": "Created",
        "expires": "Expires",
        "by": "by",
        "result_not_found": "Result not found",
        "result_expired": "This result has expired or does not exist.",
        "api_docs": "API",
        "prefix": "Prefix",
        "next_hop": "Next Hop",
        "as_path": "AS Path",
        "origin": "Origin",
        "lp": "LP",
        "med": "MED",
        "communities": "Communities",
        "rpki": "RPKI",
        "rpki_valid": "Valid",
        "rpki_invalid": "Invalid",
        "rpki_not_found": "Not found",
        "live": "live",
        "invalid_credentials": "Invalid username or password",
        "new_query": "New query",
        "run_new_query": "Run a new query",
        "recent_queries_7d": "Recent queries from the last 7 days",
        "run_query_to_appear": "Run a query to see it appear here.",
        "select_all": "Select all",
        "clear_selection": "Clear",
        "devices_queried": "devices queried",
        "total_time": "Total time",
        "compare": "Compare",
        "diff": "Diff",
        "side_by_side": "Side by side",
        "stacked": "Stacked",
        "n_selected": "selected",
        "resolved_to": "resolved to",
        "other_looking_glasses": "Other Looking Glasses",
    },
    "ru": {
        "site_name": "bgpeek",
        "network_query": "Сетевой запрос",
        "location": "Точка",
        "select_device": "— выберите устройство —",
        "query_type": "Тип запроса",
        "bgp_route": "BGP маршрут",
        "ping": "Ping",
        "traceroute": "Traceroute",
        "target": "Цель",
        "run_query": "Выполнить",
        "abort": "Отмена",
        "running": "выполняется…",
        "empty_state": "Выполните запрос для просмотра результатов",
        "cached": "из кэша",
        "show_raw": "Показать raw вывод",
        "share": "Поделиться",
        "copied": "Скопировано!",
        "login": "Войти",
        "logout": "Выйти",
        "sign_in": "Войти",
        "username": "Имя пользователя",
        "password": "Пароль",
        "history": "История",
        "query_history": "История запросов",
        "recent_queries": "Последние запросы",
        "time": "Время",
        "device": "Устройство",
        "runtime": "Время выполнения",
        "status": "Статус",
        "actions": "Действия",
        "view": "Открыть",
        "load_more": "Загрузить ещё",
        "no_results": "Запросов пока нет",
        "shared_result": "Результат запроса",
        "created": "Создан",
        "expires": "Истекает",
        "by": "от",
        "result_not_found": "Результат не найден",
        "result_expired": "Этот результат истёк или не существует.",
        "api_docs": "API",
        "prefix": "Префикс",
        "next_hop": "Next Hop",
        "as_path": "AS Path",
        "origin": "Origin",
        "lp": "LP",
        "med": "MED",
        "communities": "Communities",
        "rpki": "RPKI",
        "rpki_valid": "Валиден",
        "rpki_invalid": "Невалиден",
        "rpki_not_found": "Не найден",
        "live": "live",
        "invalid_credentials": "Неверное имя пользователя или пароль",
        "new_query": "Новый запрос",
        "run_new_query": "Выполнить новый запрос",
        "recent_queries_7d": "Последние запросы за 7 дней",
        "run_query_to_appear": "Выполните запрос, и он появится здесь.",
        "select_all": "Выбрать все",
        "clear_selection": "Очистить",
        "devices_queried": "устройств опрошено",
        "total_time": "Общее время",
        "compare": "Сравнить",
        "diff": "Различия",
        "side_by_side": "Рядом",
        "stacked": "Друг под другом",
        "n_selected": "выбрано",
        "resolved_to": "разрешён в",
        "other_looking_glasses": "Другие Looking Glass",
    },
}

DEFAULT_LANG = "en"
SUPPORTED_LANGS = frozenset(TRANSLATIONS.keys())


def get_translations(lang: str) -> dict[str, str]:
    """Return translations for the given language, falling back to English."""
    return TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANG])


def detect_language(
    query_param: str | None,
    cookie: str | None,
    accept_language: str | None,
    default: str,
) -> str:
    """Detect language from request context, in priority order.

    1. ``?lang=`` query parameter
    2. ``bgpeek_lang`` cookie
    3. ``Accept-Language`` header (first supported match)
    4. Application default
    """
    for candidate in (query_param, cookie):
        if candidate and candidate in SUPPORTED_LANGS:
            return candidate

    if accept_language:
        for part in accept_language.split(","):
            tag = part.split(";")[0].strip().lower()
            # Accept both "ru" and "ru-RU" style tags.
            short = tag[:2]
            if short in SUPPORTED_LANGS:
                return short

    return default if default in SUPPORTED_LANGS else DEFAULT_LANG
