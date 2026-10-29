import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
# The KEV fixture's CVEs, in catalogue order; each has a recorded CVE record in fixtures/cve/.
CVE_IDS = ["CVE-2021-44228", "CVE-2023-4966", "CVE-2017-0144", "CVE-2024-3400", "CVE-2026-41709"]


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


@pytest.fixture
def cve_texts() -> dict[str, str]:
    return {i: (FIXTURES / "cve" / f"{i}.json").read_text(encoding="utf-8") for i in CVE_IDS}
