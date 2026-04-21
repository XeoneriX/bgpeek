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

    def test_fallback_to_english_for_unknown(self) -> None:
        t = get_translations("xx")
        assert t is TRANSLATIONS["en"]

    def test_no_empty_values(self) -> None:
        for lang_code in SUPPORTED_LANGS:
            for key, value in TRANSLATIONS[lang_code].items():
                assert value, f"Empty value for {lang_code}.{key}"


class TestDetectLanguage:
    def test_query_param_wins(self) -> None:
        assert detect_language("en", None, None, "en") == "en"

    def test_default_used_when_nothing_matches(self) -> None:
        assert detect_language(None, None, None, "en") == "en"

    def test_invalid_query_param_ignored(self) -> None:
        assert detect_language("xx", None, None, "en") == "en"

    def test_invalid_cookie_ignored(self) -> None:
        assert detect_language(None, "zz", None, "en") == "en"

    def test_accept_language_ignores_unsupported(self) -> None:
        assert detect_language(None, None, "fr-FR,de;q=0.9", "en") == "en"

    def test_accept_language_partial_match(self) -> None:
        assert detect_language(None, None, "en-US,en;q=0.9", "en") == "en"

    def test_invalid_default_falls_back(self) -> None:
        assert detect_language(None, None, None, "xx") == DEFAULT_LANG

    def test_enabled_allow_list_filters_query_param(self) -> None:
        # ru would otherwise win; allow-list restricts to en only.
        assert detect_language("ru", None, None, "en", enabled=("en",)) == "en"

    def test_enabled_allow_list_filters_cookie(self) -> None:
        assert detect_language(None, "ru", None, "en", enabled=("en",)) == "en"

    def test_enabled_allow_list_filters_accept_language(self) -> None:
        assert detect_language(None, None, "ru,en;q=0.8", "en", enabled=("en",)) == "en"

    def test_enabled_allow_list_accepts_explicit_match(self) -> None:
        # ru is still allowed when it's in the allow-list.
        assert detect_language("ru", None, None, "en", enabled=("en", "ru")) == "ru"


class TestConfigEnabledLanguages:
    """Validator behaviour for BGPEEK_ENABLED_LANGUAGES."""

    def test_default_is_en_ru(self) -> None:
        from bgpeek.config import Settings

        s = Settings()
        assert s.enabled_languages_list == ("en", "ru")

    def test_single_language(self) -> None:
        from bgpeek.config import Settings

        s = Settings(enabled_languages="en")
        assert s.enabled_languages_list == ("en",)

    def test_normalises_whitespace_and_case(self) -> None:
        from bgpeek.config import Settings

        s = Settings(enabled_languages="EN , ru  ")
        assert s.enabled_languages_list == ("en", "ru")

    def test_deduplicates(self) -> None:
        from bgpeek.config import Settings

        s = Settings(enabled_languages="en,ru,en")
        assert s.enabled_languages_list == ("en", "ru")

    def test_empty_rejected(self) -> None:
        import pytest
        from pydantic import ValidationError

        from bgpeek.config import Settings

        with pytest.raises(ValidationError, match="at least one"):
            Settings(enabled_languages="")

    def test_unknown_code_rejected(self) -> None:
        import pytest
        from pydantic import ValidationError

        from bgpeek.config import Settings

        with pytest.raises(ValidationError, match="unknown code"):
            Settings(enabled_languages="en,xx")

    def test_default_lang_must_be_in_allow_list(self) -> None:
        import pytest
        from pydantic import ValidationError

        from bgpeek.config import Settings

        with pytest.raises(ValidationError, match="not in enabled_languages"):
            Settings(default_lang="ru", enabled_languages="en")


class TestI18nMiddleware:
    """Test that the middleware sets language on actual HTTP requests."""

    def test_index_defaults_to_english(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Network Query" in resp.text

    def test_html_lang_attribute(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp_en = client.get("/")
        assert 'lang="en"' in resp_en.text

    def test_login_page_renders(self) -> None:
        from fastapi.testclient import TestClient

        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert "Username" in resp.text
        assert "Password" in resp.text

    def test_disabled_language_query_is_ignored(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from fastapi.testclient import TestClient

        from bgpeek import config as config_mod
        from bgpeek.main import app
        from bgpeek.main import settings as main_settings

        monkeypatch.setattr(main_settings, "enabled_languages", "en")
        monkeypatch.setattr(config_mod.settings, "enabled_languages", "en")

        client = TestClient(app)
        resp = client.get("/?lang=ru")
        assert resp.status_code == 200
        # `ru` was disallowed — UI must stay English and no cookie must be written.
        assert 'lang="en"' in resp.text
        assert "bgpeek_lang" not in resp.headers.get("set-cookie", "")
