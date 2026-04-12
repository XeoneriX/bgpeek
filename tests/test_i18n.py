"""Tests for the i18n module and language detection."""

from __future__ import annotations

from bgpeek.core.i18n import (
    DEFAULT_LANG,
    SUPPORTED_LANGS,
    TRANSLATIONS,
    detect_language,
    get_translations,
)


class TestGetTranslations:
    def test_returns_english(self) -> None:
        t = get_translations("en")
        assert t["network_query"] == "Network Query"

    def test_returns_russian(self) -> None:
        t = get_translations("ru")
        assert t["network_query"] == "Сетевой запрос"

    def test_fallback_to_english_for_unknown(self) -> None:
        t = get_translations("xx")
        assert t is TRANSLATIONS["en"]

    def test_all_keys_match_across_languages(self) -> None:
        en_keys = set(TRANSLATIONS["en"].keys())
        ru_keys = set(TRANSLATIONS["ru"].keys())
        missing_in_ru = en_keys - ru_keys
        missing_in_en = ru_keys - en_keys
        assert not missing_in_ru, f"Keys missing in 'ru': {missing_in_ru}"
        assert not missing_in_en, f"Keys missing in 'en': {missing_in_en}"

    def test_no_empty_values(self) -> None:
        for lang_code in SUPPORTED_LANGS:
            for key, value in TRANSLATIONS[lang_code].items():
                assert value, f"Empty value for {lang_code}.{key}"


class TestDetectLanguage:
    def test_query_param_wins(self) -> None:
        assert detect_language("ru", "en", "en", "en") == "ru"

    def test_cookie_second_priority(self) -> None:
        assert detect_language(None, "ru", "en", "en") == "ru"

    def test_accept_language_third_priority(self) -> None:
        assert detect_language(None, None, "ru-RU,ru;q=0.9,en;q=0.8", "en") == "ru"

    def test_default_used_when_nothing_matches(self) -> None:
        assert detect_language(None, None, None, "en") == "en"

    def test_invalid_query_param_ignored(self) -> None:
        assert detect_language("xx", None, None, "en") == "en"

    def test_invalid_cookie_ignored(self) -> None:
        assert detect_language(None, "zz", None, "en") == "en"

    def test_accept_language_ignores_unsupported(self) -> None:
        assert detect_language(None, None, "fr-FR,de;q=0.9", "en") == "en"

    def test_accept_language_partial_match(self) -> None:
        assert detect_language(None, None, "en-US,en;q=0.9", "ru") == "en"

    def test_invalid_default_falls_back(self) -> None:
        assert detect_language(None, None, None, "xx") == DEFAULT_LANG


class TestI18nMiddleware:
    """Test that the middleware sets language on actual HTTP requests."""

    def test_index_defaults_to_english(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Network Query" in resp.text

    def test_index_renders_russian_via_query_param(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/?lang=ru")
        assert resp.status_code == 200
        assert "Сетевой запрос" in resp.text

    def test_lang_cookie_is_set(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/?lang=ru")
        assert "bgpeek_lang" in resp.cookies
        assert resp.cookies["bgpeek_lang"] == "ru"

    def test_cookie_persists_language(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app, cookies={"bgpeek_lang": "ru"})
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Сетевой запрос" in resp.text

    def test_html_lang_attribute(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp_en = client.get("/")
        assert 'lang="en"' in resp_en.text

        resp_ru = client.get("/?lang=ru")
        assert 'lang="ru"' in resp_ru.text

    def test_login_page_translates(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/auth/login?lang=ru")
        assert resp.status_code == 200
        assert "Имя пользователя" in resp.text
        assert "Пароль" in resp.text
