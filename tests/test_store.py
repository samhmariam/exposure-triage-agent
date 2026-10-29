from datetime import UTC, date, datetime

import pytest

from triage.feeds.epss import parse_epss
from triage.feeds.kev import parse_kev
from triage.store import connect, feed_stats, load_epss, load_kev

DAY1 = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
DAY2 = datetime(2026, 10, 29, 9, 0, tzinfo=UTC)


@pytest.fixture
def con(tmp_path):
    con = connect(tmp_path / "triage.duckdb")
    yield con
    con.close()


def count(con, table):
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_load_records_fetched_at_and_raw_path(con, kev_text):
    assert load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-28.json", DAY1) == 5
    rows = con.execute("SELECT DISTINCT fetched_at, raw_path FROM kev").fetchall()
    assert rows == [(DAY1.replace(tzinfo=None), "raw/kev/2026-10-28.json")]


def test_reload_is_idempotent(con, kev_text, epss_text):
    for _ in range(2):
        load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-28.json", DAY1)
        load_epss(con, parse_epss(epss_text).data, "raw/epss/2026-10-28.json", DAY1)
    assert (count(con, "kev"), count(con, "epss"), count(con, "snapshots")) == (5, 4, 2)


def test_history_across_days_is_kept(con, kev_text):
    load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-28.json", DAY1)
    load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-29.json", DAY2)
    assert count(con, "kev") == 10


def test_stats_report_kev_count_and_epss_coverage(con, kev_text, epss_text):
    catalog = parse_kev(kev_text)
    load_kev(con, catalog, "raw/kev/2026-10-29.json", DAY2)
    load_epss(con, parse_epss(epss_text).data, "raw/epss/2026-10-29.json", DAY2)
    stats = feed_stats(con)
    assert stats.kev_count == 5
    assert stats.kev_catalog_version == "2026.10.28"
    assert stats.kev_fetched_at == DAY2
    known = sum(v.known_ransomware_campaign_use == "Known" for v in catalog.vulnerabilities)
    assert stats.ransomware_known == known
    assert stats.epss_covered == 4
    assert stats.epss_score_date == date(2026, 10, 28)


def test_stats_use_latest_snapshot(con, kev_text, epss_text):
    catalog = parse_kev(kev_text)
    smaller = catalog.model_copy(
        update={"vulnerabilities": catalog.vulnerabilities[:3], "count": 3}
    )
    load_kev(con, catalog, "raw/kev/2026-10-28.json", DAY1)
    load_kev(con, smaller, "raw/kev/2026-10-29.json", DAY2)
    load_epss(con, parse_epss(epss_text).data, "raw/epss/2026-10-29.json", DAY2)
    stats = feed_stats(con)
    assert stats.kev_count == 3
    # CVE-2017-0144 (third entry) has no EPSS score in the fixture.
    assert stats.epss_covered == 2


def test_stats_are_none_before_any_load(con):
    assert feed_stats(con) is None
