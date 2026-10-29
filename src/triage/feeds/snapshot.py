"""Raw feed snapshots: verbatim response bodies kept as evidence under data/raw/<source>/.

Snapshots are never overwritten. A normal run writes <date>.json; a forced re-download
writes <date>T<HHMMSS>Z.json beside it.
"""

import hashlib
import os
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, model_validator

from triage.http import HttpResponse


class RawResponse(BaseModel):
    """One HTTP response exactly as received."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_attribute_docstrings=True)

    url: str
    """Final request URL, including the query string."""
    status_code: int
    """HTTP status."""
    sha256: str
    """SHA-256 of the UTF-8 body; checked on every read."""
    body: str
    """Verbatim response text."""

    @model_validator(mode="after")
    def _hash_matches(self) -> Self:
        if _sha256(self.body) != self.sha256:
            raise ValueError("sha256 does not match body; the snapshot was altered or corrupted")
        return self


class Snapshot(BaseModel):
    """All responses from one fetch of one source."""

    model_config = ConfigDict(frozen=True, extra="forbid", use_attribute_docstrings=True)

    source: str
    """Feed name, e.g. kev or epss."""
    fetched_at: AwareDatetime
    """When the fetch started (UTC)."""
    responses: tuple[RawResponse, ...]
    """The responses, in request order."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def source_dir(data_dir: Path, source: str) -> Path:
    return data_dir / "raw" / source


def write_snapshot(
    data_dir: Path,
    source: str,
    fetched_at: datetime,
    responses: Sequence[HttpResponse],
    *,
    forced: bool = False,
) -> Path:
    utc = fetched_at.astimezone(UTC)
    name = f"{utc:%Y-%m-%dT%H%M%SZ}.json" if forced else f"{utc:%Y-%m-%d}.json"
    path = source_dir(data_dir, source) / name
    if path.exists():
        raise FileExistsError(f"refusing to overwrite raw snapshot {path}")
    snapshot = Snapshot(
        source=source,
        fetched_at=utc,
        responses=tuple(
            RawResponse(url=r.url, status_code=r.status_code, sha256=_sha256(r.text), body=r.text)
            for r in responses
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic: readers never see a half-written snapshot
    return path


def read_snapshot(path: Path) -> Snapshot:
    return Snapshot.model_validate_json(path.read_text(encoding="utf-8"))


def latest_for(data_dir: Path, source: str, day: date) -> Path | None:
    """Newest snapshot of `day`. Forced names (<date>T...) sort after <date>.json, then by time."""
    folder = source_dir(data_dir, source)
    if not folder.is_dir():
        return None
    prefix = day.isoformat()
    matches = sorted(p for p in folder.glob(f"{prefix}*.json") if p.name[len(prefix)] in {".", "T"})
    return matches[-1] if matches else None
