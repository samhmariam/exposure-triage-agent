import json
from datetime import UTC, datetime

import httpx
import pytest

from triage.cli import main
from triage.http import HttpClient

NOW = datetime(2026, 10, 29, 9, 12, 3, tzinfo=UTC)


@pytest.fixture
def feeds(kev_text, epss_text):
    """A fake CISA + FIRST that serves the recorded fixtures and counts calls."""
    state = {"calls": 0, "kev": kev_text}

    def handler(request):
        state["calls"] += 1
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, text=state["kev"])
        if request.url.host == "api.first.org":
            return httpx.Response(200, text=epss_text)
        return httpx.Response(404)

    state["client"] = HttpClient(transport=httpx.MockTransport(handler))
    return state


def run(tmp_path, feeds, *args):
    argv = ["--data-dir", str(tmp_path), "feeds", *args]
    return main(argv, client=feeds["client"], clock=lambda: NOW)


def test_refresh_writes_raw_snapshots_and_database(tmp_path, feeds):
    assert run(tmp_path, feeds, "refresh") == 0
    assert (tmp_path / "raw" / "kev" / "2026-10-29.json").is_file()
    assert (tmp_path / "raw" / "epss" / "2026-10-29.json").is_file()
    assert (tmp_path / "triage.duckdb").is_file()
    assert feeds["calls"] == 2  # 1 KEV + 1 EPSS batch (5 CVEs)


def test_second_refresh_reuses_todays_snapshots(tmp_path, feeds):
    run(tmp_path, feeds, "refresh")
    calls = feeds["calls"]
    assert run(tmp_path, feeds, "refresh") == 0
    assert feeds["calls"] == calls


def test_forced_refresh_downloads_into_new_files(tmp_path, feeds):
    run(tmp_path, feeds, "refresh")
    calls = feeds["calls"]
    assert run(tmp_path, feeds, "refresh", "--force") == 0
    assert feeds["calls"] == calls + 2
    assert (tmp_path / "raw" / "kev" / "2026-10-29T091203Z.json").is_file()
    assert (tmp_path / "raw" / "kev" / "2026-10-29.json").is_file()


def test_stats_print_kev_count_and_epss_coverage(tmp_path, feeds, capsys):
    run(tmp_path, feeds, "refresh")
    capsys.readouterr()
    assert run(tmp_path, feeds, "stats") == 0
    out = capsys.readouterr().out
    assert "catalogue 2026.10.28" in out
    assert "5 CVEs" in out
    assert "EPSS coverage: 4/5 KEV CVEs (80.0%)" in out


def test_stats_before_refresh_explains_what_to_do(tmp_path, feeds, capsys):
    assert run(tmp_path, feeds, "stats") == 1
    assert "triage feeds refresh" in capsys.readouterr().err


def test_invalid_feed_is_kept_as_evidence_but_not_loaded(tmp_path, feeds, capsys):
    bad = json.loads(feeds["kev"])
    bad["count"] = 99
    feeds["kev"] = json.dumps(bad)
    assert run(tmp_path, feeds, "refresh") == 1
    assert "count" in capsys.readouterr().err
    assert (tmp_path / "raw" / "kev" / "2026-10-29.json").is_file()
    assert run(tmp_path, feeds, "stats") == 1
