"""DuckDB store for ingested feeds. Each row keeps the raw snapshot it came from (raw_path).

Timestamps are stored as naive UTC TIMESTAMPs and returned timezone-aware.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

import duckdb
from pydantic import JsonValue

from triage.feeds.cve_records import Coverage, CveRecord, classify
from triage.feeds.epss import EpssScore
from triage.feeds.kev import KevCatalog

DB_FILENAME = "triage.duckdb"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    raw_path VARCHAR PRIMARY KEY,
    source VARCHAR NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    record_count INTEGER NOT NULL,
    catalog_version VARCHAR
);
CREATE TABLE IF NOT EXISTS kev (
    cve_id VARCHAR NOT NULL,
    vendor_project VARCHAR NOT NULL,
    product VARCHAR NOT NULL,
    vulnerability_name VARCHAR NOT NULL,
    date_added DATE NOT NULL,
    short_description VARCHAR NOT NULL,
    required_action VARCHAR NOT NULL,
    due_date DATE NOT NULL,
    known_ransomware_campaign_use VARCHAR NOT NULL,
    notes VARCHAR NOT NULL,
    cwes VARCHAR[] NOT NULL,
    catalog_version VARCHAR NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    raw_path VARCHAR NOT NULL,
    PRIMARY KEY (cve_id, raw_path)
);
CREATE TABLE IF NOT EXISTS epss (
    cve_id VARCHAR NOT NULL,
    epss DOUBLE NOT NULL,
    percentile DOUBLE NOT NULL,
    score_date DATE NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    raw_path VARCHAR NOT NULL,
    PRIMARY KEY (cve_id, raw_path)
);
CREATE TABLE IF NOT EXISTS cve_records (
    cve_id VARCHAR NOT NULL,
    state VARCHAR NOT NULL,
    assigner VARCHAR,
    date_updated TIMESTAMP,
    descriptions JSON NOT NULL,
    refs JSON NOT NULL,
    affected JSON NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    raw_path VARCHAR NOT NULL,
    PRIMARY KEY (cve_id, raw_path)
);
"""


@dataclass(frozen=True)
class FeedStats:
    """Summary of the latest KEV and EPSS snapshots."""

    kev_count: int
    kev_catalog_version: str
    kev_fetched_at: datetime
    ransomware_known: int
    epss_covered: int
    epss_score_date: date | None
    epss_fetched_at: datetime | None


@dataclass(frozen=True)
class CoverageReport:
    """How the latest KEV snapshot's CVEs split into coverage buckets."""

    kev_count: int
    cve_raw_path: str
    counts: dict[Coverage, int]


def connect(path: Path) -> duckdb.DuckDBPyConnection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    con.execute(_SCHEMA)
    return con


def _naive_utc(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(tzinfo=None)


def _replace_snapshot(
    con: duckdb.DuckDBPyConnection,
    table: str,
    source: str,
    raw_path: str,
    fetched_at: datetime,
    rows: list[tuple[object, ...]],
    catalog_version: str | None,
) -> int:
    """Load one snapshot's rows atomically; loading the same raw_path again replaces them."""
    placeholders = ", ".join("?" * len(rows[0])) if rows else ""
    con.begin()
    try:
        con.execute(f"DELETE FROM {table} WHERE raw_path = ?", [raw_path])
        if rows:
            con.executemany(f"INSERT INTO {table} VALUES ({placeholders})", rows)
        con.execute(
            "INSERT OR REPLACE INTO snapshots VALUES (?, ?, ?, ?, ?)",
            [raw_path, source, _naive_utc(fetched_at), len(rows), catalog_version],
        )
        con.commit()
    except Exception:
        con.rollback()
        raise
    return len(rows)


def load_kev(
    con: duckdb.DuckDBPyConnection, catalog: KevCatalog, raw_path: str, fetched_at: datetime
) -> int:
    ts = _naive_utc(fetched_at)
    rows: list[tuple[object, ...]] = [
        (
            v.cve_id,
            v.vendor_project,
            v.product,
            v.vulnerability_name,
            v.date_added,
            v.short_description,
            v.required_action,
            v.due_date,
            v.known_ransomware_campaign_use,
            v.notes,
            list(v.cwes),
            catalog.catalog_version,
            ts,
            raw_path,
        )
        for v in catalog.vulnerabilities
    ]
    return _replace_snapshot(con, "kev", "kev", raw_path, fetched_at, rows, catalog.catalog_version)


def load_epss(
    con: duckdb.DuckDBPyConnection,
    scores: Sequence[EpssScore],
    raw_path: str,
    fetched_at: datetime,
) -> int:
    ts = _naive_utc(fetched_at)
    rows: list[tuple[object, ...]] = [
        (s.cve, s.epss, s.percentile, s.date, ts, raw_path) for s in scores
    ]
    return _replace_snapshot(con, "epss", "epss", raw_path, fetched_at, rows, None)


def _json(parts: Sequence[JsonValue]) -> str:
    return json.dumps(list(parts), ensure_ascii=False)


def load_cve_records(
    con: duckdb.DuckDBPyConnection,
    records: Sequence[CveRecord],
    raw_path: str,
    fetched_at: datetime,
) -> int:
    ts = _naive_utc(fetched_at)
    rows: list[tuple[object, ...]] = [
        (
            r.cve_metadata.cve_id,
            r.cve_metadata.state,
            r.cve_metadata.assigner_short_name,
            _naive_utc(r.cve_metadata.date_updated) if r.cve_metadata.date_updated else None,
            _json(r.containers.cna.descriptions),
            _json(r.containers.cna.references),
            _json(r.containers.cna.affected),
            ts,
            raw_path,
        )
        for r in records
    ]
    return _replace_snapshot(con, "cve_records", "cve", raw_path, fetched_at, rows, None)


def _latest(con: duckdb.DuckDBPyConnection, source: str) -> tuple[str, datetime, str | None] | None:
    return con.execute(
        "SELECT raw_path, fetched_at, catalog_version FROM snapshots WHERE source = ? "
        "ORDER BY fetched_at DESC, raw_path DESC LIMIT 1",
        [source],
    ).fetchone()


def feed_stats(con: duckdb.DuckDBPyConnection) -> FeedStats | None:
    """Stats over the latest KEV snapshot; None if no KEV snapshot is loaded."""
    kev = _latest(con, "kev")
    if kev is None:
        return None
    kev_path, kev_fetched, version = kev
    kev_count, ransomware_known = con.execute(
        "SELECT count(*), count(*) FILTER (WHERE known_ransomware_campaign_use = 'Known') "
        "FROM kev WHERE raw_path = ?",
        [kev_path],
    ).fetchone()
    covered, score_date, epss_fetched = 0, None, None
    epss = _latest(con, "epss")
    if epss is not None:
        epss_path, epss_fetched, _ = epss
        covered, score_date = con.execute(
            "SELECT count(e.cve_id), max(e.score_date) FROM kev k "
            "JOIN epss e ON e.cve_id = k.cve_id AND e.raw_path = ? WHERE k.raw_path = ?",
            [epss_path, kev_path],
        ).fetchone()
    return FeedStats(
        kev_count=kev_count,
        kev_catalog_version=version or "",
        kev_fetched_at=kev_fetched.replace(tzinfo=UTC),
        ransomware_known=ransomware_known,
        epss_covered=covered,
        epss_score_date=score_date,
        epss_fetched_at=epss_fetched.replace(tzinfo=UTC) if epss_fetched else None,
    )


def cve_coverage(con: duckdb.DuckDBPyConnection) -> CoverageReport | None:
    """Bucket every CVE of the latest KEV snapshot by the latest CVE-record snapshot.

    None if either snapshot is missing. A KEV CVE without a record row counts as NO_RECORD.
    """
    kev, cve = _latest(con, "kev"), _latest(con, "cve")
    if kev is None or cve is None:
        return None
    rows = con.execute(
        "SELECT c.state, c.affected FROM kev k "
        "LEFT JOIN cve_records c ON c.cve_id = k.cve_id AND c.raw_path = ? WHERE k.raw_path = ?",
        [cve[0], kev[0]],
    ).fetchall()
    counts = dict.fromkeys(Coverage, 0)
    for state, affected in rows:
        counts[classify(state, json.loads(affected) if affected is not None else None)] += 1
    return CoverageReport(kev_count=len(rows), cve_raw_path=cve[0], counts=counts)
