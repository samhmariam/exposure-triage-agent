"""`triage` command line: `triage feeds refresh [--force]`, `stats` and `coverage`."""

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from triage.feeds import cve_records, epss, kev
from triage.feeds.cve_records import Coverage
from triage.feeds.snapshot import Snapshot, latest_for, read_snapshot, write_snapshot
from triage.http import HttpClient, HttpError, HttpResponse
from triage.store import (
    DB_FILENAME,
    connect,
    cve_coverage,
    feed_stats,
    load_cve_records,
    load_epss,
    load_kev,
)

Clock = Callable[[], datetime]
Download = Callable[[], tuple[Sequence[HttpResponse], Sequence[str]]]
"""Fetches one source: the responses, and the requested items the source answered 404 for."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triage", description="Exposure triage agent.")
    parser.add_argument("--data-dir", type=Path, default=Path("data"), help="default: ./data")
    commands = parser.add_subparsers(dest="command", required=True)
    feeds = commands.add_parser("feeds", help="ingest feeds (CISA KEV, FIRST EPSS, CVE records)")
    actions = feeds.add_subparsers(dest="action", required=True)
    refresh = actions.add_parser("refresh", help="download (or reuse today's) feeds and load them")
    refresh.add_argument(
        "--force", action="store_true", help="download again into a new timestamped snapshot"
    )
    actions.add_parser("stats", help="show KEV count and EPSS coverage")
    actions.add_parser(
        "coverage", help="count KEV CVEs whose CVE record has version ranges, products, or nothing"
    )
    return parser


class _LazyClient:
    """Creates the real HttpClient only if a download is actually needed."""

    def __init__(self, client: HttpClient | None) -> None:
        self._client = client
        self._owned = False

    def get(self) -> HttpClient:
        if self._client is None:
            self._client = HttpClient()
            self._owned = True
        return self._client

    def close(self) -> None:
        if self._owned and self._client is not None:
            self._client.close()


def _snapshot(
    data_dir: Path,
    source: str,
    now: datetime,
    force: bool,
    download: Download,
) -> tuple[Path, Snapshot, str]:
    existing = None if force else latest_for(data_dir, source, now.astimezone(UTC).date())
    if existing is not None:
        return existing, read_snapshot(existing), "reused"
    responses, missing = download()
    path = write_snapshot(data_dir, source, now, responses, forced=force, missing=missing)
    return path, read_snapshot(path), "downloaded"


def _refresh(data_dir: Path, force: bool, client: _LazyClient, now: datetime) -> None:
    kev_path, kev_snap, how = _snapshot(
        data_dir, "kev", now, force, lambda: ([kev.fetch_kev(client.get())], ())
    )
    catalog = kev.parse_kev(kev_snap.responses[0].body)  # validate before anything is loaded
    print(f"kev:  {how} {kev_path.relative_to(data_dir).as_posix()} ({catalog.count} entries)")

    cve_ids = [v.cve_id for v in catalog.vulnerabilities]
    epss_path, epss_snap, how = _snapshot(
        data_dir, "epss", now, force, lambda: (epss.fetch_epss(client.get(), cve_ids), ())
    )
    scores = [s for r in epss_snap.responses for s in epss.parse_epss(r.body).data]
    print(
        f"epss: {how} {epss_path.relative_to(data_dir).as_posix()} "
        f"({len(scores)} scores from {len(epss_snap.responses)} responses)"
    )

    def fetch_records() -> tuple[list[HttpResponse], list[str]]:
        print(f"cve:  downloading {len(cve_ids)} CVE records (one request each)...")
        return cve_records.fetch_cve_records(client.get(), cve_ids)

    cve_path, cve_snap, how = _snapshot(data_dir, "cve", now, force, fetch_records)
    records = [  # validate every record before anything is loaded
        cve_records.parse_cve_record(r.body, r.url.rsplit("/", 1)[-1]) for r in cve_snap.responses
    ]
    print(
        f"cve:  {how} {cve_path.relative_to(data_dir).as_posix()} "
        f"({len(records)} records, {len(cve_snap.missing)} not found)"
    )

    con = connect(data_dir / DB_FILENAME)
    try:
        load_kev(con, catalog, kev_path.relative_to(data_dir).as_posix(), kev_snap.fetched_at)
        load_epss(con, scores, epss_path.relative_to(data_dir).as_posix(), epss_snap.fetched_at)
        load_cve_records(
            con, records, cve_path.relative_to(data_dir).as_posix(), cve_snap.fetched_at
        )
    finally:
        con.close()


def _stats(data_dir: Path) -> int:
    db = data_dir / DB_FILENAME
    stats = None
    if db.exists():
        con = connect(db)
        try:
            stats = feed_stats(con)
        finally:
            con.close()
    if stats is None:
        print("no feed data loaded; run `triage feeds refresh` first", file=sys.stderr)
        return 1
    fetched = f"{stats.kev_fetched_at:%Y-%m-%dT%H:%M:%SZ}"
    print(
        f"KEV  catalogue {stats.kev_catalog_version}, fetched {fetched}: "
        f"{stats.kev_count} CVEs (ransomware use known: {stats.ransomware_known})"
    )
    pct = 100 * stats.epss_covered / stats.kev_count if stats.kev_count else 0.0
    dated = f", scores dated {stats.epss_score_date}" if stats.epss_score_date else ""
    print(f"EPSS coverage: {stats.epss_covered}/{stats.kev_count} KEV CVEs ({pct:.1f}%){dated}")
    return 0


_COVERAGE_LABELS = {
    Coverage.VERSION_RANGES: "structured version ranges",
    Coverage.PRODUCT_ONLY: "product names only",
    Coverage.NOTHING: "nothing",
    Coverage.REJECTED: "rejected",
    Coverage.NO_RECORD: "no record",
}


def _coverage(data_dir: Path) -> int:
    """Print counts only: record text is untrusted and never reaches the terminal."""
    db = data_dir / DB_FILENAME
    report = None
    if db.exists():
        con = connect(db)
        try:
            report = cve_coverage(con)
        finally:
            con.close()
    if report is None:
        print("no CVE records loaded; run `triage feeds refresh` first", file=sys.stderr)
        return 1
    print(f"CVE records for {report.kev_count} KEV CVEs ({report.cve_raw_path}):")
    for bucket, label in _COVERAGE_LABELS.items():
        n = report.counts[bucket]
        pct = 100 * n / report.kev_count if report.kev_count else 0.0
        print(f"  {label:<27}{n:>6}  {pct:5.1f}%")
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    client: HttpClient | None = None,
    clock: Clock | None = None,
) -> int:
    args = _parser().parse_args(argv)
    now = (clock or (lambda: datetime.now(UTC)))()
    if args.action == "stats":
        return _stats(args.data_dir)
    if args.action == "coverage":
        return _coverage(args.data_dir)
    lazy = _LazyClient(client)
    try:
        _refresh(args.data_dir, args.force, lazy, now)
    except (HttpError, ValueError, FileExistsError) as exc:  # ValidationError is a ValueError
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        lazy.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
