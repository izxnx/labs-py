"""Спільні фікстури тестів ЛР №4."""

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Прибирає успадкований ключ і забороняє справжні запити Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")
