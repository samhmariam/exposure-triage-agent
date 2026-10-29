import hashlib
import json
from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from triage.feeds.snapshot import latest_for, read_snapshot, write_snapshot
from triage.http import HttpResponse

FETCHED = datetime(2026, 10, 29, 9, 12, 3, tzinfo=UTC)
RESPONSE = HttpResponse(url="https://feeds.example/kev.json", status_code=200, text='{"a": 1}\n')


def test_path_layout(tmp_path):
    path = write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    assert path == tmp_path / "raw" / "kev" / "2026-10-29.json"


def test_forced_snapshot_gets_timestamped_name(tmp_path):
    path = write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE], forced=True)
    assert path.name == "2026-10-29T091203Z.json"


def test_body_is_verbatim_and_hashed(tmp_path):
    snap = read_snapshot(write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE]))
    assert snap.source == "kev"
    assert snap.fetched_at == FETCHED
    (raw,) = snap.responses
    assert raw.body == RESPONSE.text
    assert raw.sha256 == hashlib.sha256(RESPONSE.text.encode("utf-8")).hexdigest()
    assert (raw.url, raw.status_code) == (RESPONSE.url, 200)


def test_tampered_body_is_rejected(tmp_path):
    path = write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["responses"][0]["body"] = '{"a": 2}\n'
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValidationError, match="sha256"):
        read_snapshot(path)


def test_existing_snapshots_are_never_overwritten(tmp_path):
    write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    with pytest.raises(FileExistsError):
        write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE], forced=True)
    with pytest.raises(FileExistsError):
        write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE], forced=True)


def test_no_temp_files_left_behind(tmp_path):
    write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    assert [p.name for p in (tmp_path / "raw" / "kev").iterdir()] == ["2026-10-29.json"]


def test_latest_for_picks_newest_snapshot_of_the_day(tmp_path):
    assert latest_for(tmp_path, "kev", date(2026, 10, 29)) is None
    write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    later = FETCHED.replace(hour=15)
    forced = write_snapshot(tmp_path, "kev", later, [RESPONSE], forced=True)
    write_snapshot(tmp_path, "epss", later.replace(hour=16), [RESPONSE], forced=True)
    assert latest_for(tmp_path, "kev", date(2026, 10, 29)) == forced
    assert latest_for(tmp_path, "kev", date(2026, 10, 30)) is None


def test_missing_ids_are_recorded(tmp_path):
    path = write_snapshot(tmp_path, "cve", FETCHED, [RESPONSE], missing=["CVE-1999-0001"])
    assert read_snapshot(path).missing == ("CVE-1999-0001",)


def test_snapshots_without_missing_field_still_read(tmp_path):
    path = write_snapshot(tmp_path, "kev", FETCHED, [RESPONSE])
    envelope = json.loads(path.read_text(encoding="utf-8"))
    del envelope["missing"]
    path.write_text(json.dumps(envelope), encoding="utf-8")
    assert read_snapshot(path).missing == ()
