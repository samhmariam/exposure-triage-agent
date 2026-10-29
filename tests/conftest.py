import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail any test that opens a real connection: tests use recorded fixtures only."""

    def guard(*args, **kwargs):
        raise RuntimeError("network access is disabled in tests; use recorded fixtures")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)


@pytest.fixture
def kev_text() -> str:
    return (FIXTURES / "kev" / "catalog.json").read_text(encoding="utf-8")


@pytest.fixture
def epss_text() -> str:
    return (FIXTURES / "epss" / "page.json").read_text(encoding="utf-8")
