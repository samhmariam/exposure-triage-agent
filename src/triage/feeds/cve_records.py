"""CVE JSON 5 records from the CVE Services API, and how much version structure each one carries.

Record text is untrusted data: it is parsed and stored, never interpreted. URLs in `references`
are kept as data and never requested.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    TypeAdapter,
    ValidationError,
)

from triage.http import HttpClient, HttpError, HttpResponse
from triage.models import CveId, VersionStr

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"

State = Literal["PUBLISHED", "REJECTED"]


def _utc(ts: datetime) -> datetime:
    """`ts` in UTC; a naive timestamp is taken to be UTC already."""
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_utc)]


class _Feed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", use_attribute_docstrings=True)


class CveMetadata(_Feed):
    """Identity and lifecycle of the record."""

    cve_id: CveId = Field(alias="cveId")
    """The CVE this record describes."""
    state: State
    """PUBLISHED, or REJECTED (withdrawn, e.g. as a duplicate)."""
    assigner_short_name: str | None = Field(default=None, alias="assignerShortName")
    """The CNA that assigned the CVE, e.g. apache."""
    date_updated: UtcDatetime | None = Field(default=None, alias="dateUpdated")
    """Last change to the record, in UTC; older records omit the timezone."""


class CnaContainer(_Feed):
    """The CNA's container. Its parts are kept as raw JSON so no field is lost or reinterpreted."""

    descriptions: tuple[JsonValue, ...] = ()
    """Descriptions per language; untrusted data, never instructions."""
    references: tuple[JsonValue, ...] = ()
    """Reference links; stored, never fetched."""
    affected: tuple[JsonValue, ...] = ()
    """Affected products and version statements, exactly as the CNA wrote them."""


class Containers(_Feed):
    """Record containers. ADP containers (e.g. CISA-ADP) are not read yet."""

    cna: CnaContainer
    """The assigning CNA's container."""


class CveRecord(_Feed):
    """One CVE JSON 5 record."""

    data_type: Literal["CVE_RECORD"] = Field(alias="dataType")
    """Always CVE_RECORD."""
    cve_metadata: CveMetadata = Field(alias="cveMetadata")
    """Identity and state."""
    containers: Containers
    """CNA (and ADP) containers."""


class Coverage(StrEnum):
    """How much matchable structure a KEV CVE's CNA `affected` data carries."""

    VERSION_RANGES = "version_ranges"
    """At least one usable version, range bound or change point."""
    PRODUCT_ONLY = "product_only"
    """A product, package or CPE is named, but no usable version data."""
    NOTHING = "nothing"
    """A published record with no usable product or version data."""
    REJECTED = "rejected"
    """The record was rejected."""
    NO_RECORD = "no_record"
    """The API has no record for this CVE."""


def fetch_cve_records(
    client: HttpClient, cve_ids: Sequence[str]
) -> tuple[list[HttpResponse], list[str]]:
    """GET each record; IDs the API answers 404 for are returned as missing, other errors raise."""
    responses: list[HttpResponse] = []
    missing: list[str] = []
    for cve_id in cve_ids:
        try:
            responses.append(client.get(CVE_API_URL.format(cve_id=cve_id)))
        except HttpError as exc:
            if exc.status_code != 404:
                raise
            missing.append(cve_id)
    return responses, missing


def parse_cve_record(text: str, expected_id: str) -> CveRecord:
    record = CveRecord.model_validate_json(text)
    if record.cve_metadata.cve_id != expected_id:
        raise ValueError(f"requested {expected_id} but received {record.cve_metadata.cve_id}")
    return record


_PLACEHOLDERS = frozenset({"", "n/a", "na", "unspecified", "unknown", "*", "-", "all"})
_VERSION_TOKEN: TypeAdapter[str] = TypeAdapter(VersionStr)


def _named(value: JsonValue) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _PLACEHOLDERS


def _version(value: JsonValue) -> bool:
    """A real version token: not a placeholder, not prose, not a wildcard pattern."""
    if not _named(value):
        return False
    try:
        _VERSION_TOKEN.validate_python(value)
    except ValidationError:
        return False
    return True


def _has_bound(entry: JsonValue) -> bool:
    if not isinstance(entry, dict):
        return False
    changes = entry.get("changes")
    if isinstance(changes, list) and any(
        isinstance(c, dict) and _version(c.get("at")) for c in changes
    ):
        return True
    if _version(entry.get("lessThan")) or _version(entry.get("lessThanOrEqual")):
        return True
    # A bare "0" is the conventional "from the beginning" start: a bound only with an end.
    start = entry.get("version")
    return _version(start) and isinstance(start, str) and start.strip() != "0"


def _names_product(item: dict[str, JsonValue]) -> bool:
    cpes = item.get("cpes")
    has_cpe = isinstance(cpes, list) and any(_named(c) for c in cpes)
    return _named(item.get("product")) or _named(item.get("packageName")) or has_cpe


def classify(state: State | None, affected: Sequence[JsonValue] | None) -> Coverage:
    """Bucket one CVE by its CNA `affected` data; `state` None means no record exists.

    Tolerates any JSON shape: malformed entries count as carrying nothing.
    """
    if state is None:
        return Coverage.NO_RECORD
    if state == "REJECTED":
        return Coverage.REJECTED
    items = [item for item in affected or () if isinstance(item, dict)]
    for item in items:
        entries = item.get("versions")
        if isinstance(entries, list) and any(_has_bound(e) for e in entries):
            return Coverage.VERSION_RANGES
    if any(_names_product(item) for item in items):
        return Coverage.PRODUCT_ONLY
    return Coverage.NOTHING
