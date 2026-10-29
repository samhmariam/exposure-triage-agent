import json
from datetime import UTC, date, datetime

import pytest

from conftest import CVE_IDS
from triage.feeds.cve_records import Coverage, parse_cve_record
from triage.feeds.epss import parse_epss
from triage.feeds.kev import parse_kev
from triage.store import (
    connect,
    cve_coverage,
    feed_stats,
    load_cve_records,
    load_epss,
    load_kev,
)

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


def cve_records(cve_texts, ids=CVE_IDS):
    return [parse_cve_record(cve_texts[i], i) for i in ids]


def test_cve_records_keep_raw_json_parts(con, cve_texts):
    assert load_cve_records(con, cve_records(cve_texts), "raw/cve/2026-10-29.json", DAY2) == 5
    row = con.execute(
        "SELECT state, assigner, date_updated, descriptions, refs, affected, raw_path "
        "FROM cve_records WHERE cve_id = 'CVE-2021-44228'"
    ).fetchone()
    cna = json.loads(cve_texts["CVE-2021-44228"])["containers"]["cna"]
    state, assigner, updated, descriptions, refs, affected, raw_path = row
    assert (state, assigner, raw_path) == ("PUBLISHED", "apache", "raw/cve/2026-10-29.json")
    assert updated == datetime(2025, 10, 21, 23, 25, 23, 121000)
    assert json.loads(descriptions) == cna["descriptions"]
    assert json.loads(refs) == cna["references"]
    assert json.loads(affected) == cna["affected"]


def test_cve_records_are_queryable_as_json(con, cve_texts):
    load_cve_records(con, cve_records(cve_texts), "raw/cve/2026-10-29.json", DAY2)
    (product,) = con.execute(
        "SELECT affected->>'$[0].product' FROM cve_records WHERE cve_id = 'CVE-2021-44228'"
    ).fetchone()
    assert product == "Apache Log4j2"


def test_cve_reload_is_idempotent(con, cve_texts):
    for _ in range(2):
        load_cve_records(con, cve_records(cve_texts), "raw/cve/2026-10-29.json", DAY2)
    assert (count(con, "cve_records"), count(con, "snapshots")) == (5, 1)


def test_coverage_counts_every_kev_cve(con, kev_text, cve_texts):
    load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-29.json", DAY2)
    # CVE-2026-41709 has no record in this snapshot (as if the API answered 404).
    load_cve_records(con, cve_records(cve_texts, CVE_IDS[:4]), "raw/cve/2026-10-29.json", DAY2)
    report = cve_coverage(con)
    assert report.kev_count == 5
    assert report.cve_raw_path == "raw/cve/2026-10-29.json"
    assert report.counts == {
        Coverage.VERSION_RANGES: 3,
        Coverage.PRODUCT_ONLY: 1,
        Coverage.NOTHING: 0,
        Coverage.REJECTED: 0,
        Coverage.NO_RECORD: 1,
    }


def test_coverage_uses_latest_cve_snapshot(con, kev_text, cve_texts):
    load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-29.json", DAY2)
    load_cve_records(con, cve_records(cve_texts, CVE_IDS[:1]), "raw/cve/2026-10-28.json", DAY1)
    load_cve_records(con, cve_records(cve_texts), "raw/cve/2026-10-29.json", DAY2)
    assert cve_coverage(con).counts[Coverage.NO_RECORD] == 0


def test_coverage_is_none_without_kev_or_cve_data(con, kev_text):
    assert cve_coverage(con) is None
    load_kev(con, parse_kev(kev_text), "raw/kev/2026-10-29.json", DAY2)
    assert cve_coverage(con) is None
