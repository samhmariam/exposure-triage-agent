"""Domain models shared by every pipeline stage.

Pure data shapes: no I/O and no version comparison. Ordering versions needs ecosystem-specific
comparators (stage 5), so these models validate structure only, never `start <= end`.
"""

from enum import StrEnum
from typing import Annotated, Self
from urllib.parse import unquote

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StrictBool,
    model_validator,
)


def _reject_blank(value: str) -> str:
    # Reject without stripping: evidence quotes must stay verbatim for the quote-in-source check.
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def _require_digit(value: str) -> str:
    if not any(c.isdigit() for c in value):
        raise ValueError("a version must contain a digit")
    return value


def _strip_purl_suffixes(purl: str) -> str:
    """Drop the `#subpath` and `?qualifiers` parts of a purl."""
    return purl.split("#", 1)[0].split("?", 1)[0]


def purl_version(purl: str) -> str | None:
    """The decoded version of a purl, or None if it has none.

    A raw `@` only ever separates the version: scoped npm names encode theirs as `%40`.
    """
    _, sep, version = _strip_purl_suffixes(purl).rpartition("@")
    return unquote(version) if sep else None


def purl_package(purl: str) -> str:
    """A purl reduced to package identity: no version, qualifiers or subpath."""
    return _strip_purl_suffixes(purl).split("@", 1)[0]


def _reject_purl_version(value: str) -> str:
    if purl_version(value) is not None:
        raise ValueError("must identify the package only, without an @version")
    return value


NonBlankStr = Annotated[str, Field(min_length=1), AfterValidator(_reject_blank)]
CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
# Shape check only (pkg:<type>/<name>...); full purl parsing belongs to normalisation.
Purl = Annotated[str, Field(pattern=r"^pkg:[a-z][a-z0-9.+-]*/\S+$")]
PackagePurl = Annotated[Purl, AfterValidator(_reject_purl_version)]
# One version token, never an expression: no spaces, commas or leading operators (< >= ^ ~).
# `~` and `:` are allowed after the first character for Debian (1.0~rc1, 1:2.0).
VersionStr = Annotated[
    str, Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$"), AfterValidator(_require_digit)
]


class _Model(BaseModel):
    # extra="forbid": an LLM inventing fields must fail validation, not be silently dropped.
    model_config = ConfigDict(frozen=True, extra="forbid", use_attribute_docstrings=True)


class Exposure(StrEnum):
    """How reachable an asset is from untrusted networks."""

    INTERNET_FACING = "internet_facing"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class Criticality(StrEnum):
    """Business impact if the asset is compromised."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Verdict for one component on one asset against one CVE."""

    AFFECTED = "affected"
    POSSIBLY_AFFECTED = "possibly_affected"
    NOT_AFFECTED = "not_affected"


class Decision(StrEnum):
    """A human reviewer's verdict on a fix proposal."""

    APPROVED = "approved"
    REJECTED = "rejected"


class AffectedRange(_Model):
    """One affected version range for a product, as stated by an advisory, with its citation."""

    vendor: NonBlankStr
    """Vendor or project name as written in the advisory."""
    product: NonBlankStr
    """Product name as written in the advisory."""
    purl: PackagePurl | None = None
    """Package identity (purl without @version), set during normalisation; None until mapped."""
    version_start: VersionStr | None
    """Lower bound; required key, null means open below. Compared only by stage 5."""
    version_end: VersionStr | None
    """Upper bound; required key, null means open above. Compared only by stage 5."""
    start_inclusive: StrictBool | None = None
    """Whether `version_start` itself is affected; required when it is set, null when open."""
    end_inclusive: StrictBool | None = None
    """Whether `version_end` itself is affected; required when it is set, null when open."""
    all_versions: StrictBool = False
    """Explicit claim that every version is affected; required for a range with no bounds."""
    evidence_quote: NonBlankStr
    """Verbatim advisory text supporting this range; kept unmodified for citation checks."""
    source_url: HttpUrl
    """URL of the advisory the quote was taken from."""

    @model_validator(mode="after")
    def _bounds_are_consistent(self) -> Self:
        has_bound = self.version_start is not None or self.version_end is not None
        if self.all_versions and has_bound:
            raise ValueError("all_versions=True must not set version_start or version_end")
        if not self.all_versions and not has_bound:
            raise ValueError("a range with no bounds must set all_versions=True explicitly")
        for side in ("start", "end"):
            bound, flag = getattr(self, f"version_{side}"), getattr(self, f"{side}_inclusive")
            if bound is not None and flag is None:
                raise ValueError(f"version_{side} is set, so {side}_inclusive is required")
            if bound is None and flag is not None:
                raise ValueError(f"version_{side} is open, so {side}_inclusive must be null")
        # Identical strings only: equivalence such as 1.0 == 1.0.0 needs stage-5 comparators.
        same = self.version_start is not None and self.version_start == self.version_end
        if same and not (self.start_inclusive and self.end_inclusive):
            raise ValueError(
                "version_start == version_end needs start_inclusive and end_inclusive "
                "both true, otherwise the range is empty"
            )
        return self


class Cve(_Model):
    """A vulnerability record from an ingest feed, with the ranges extracted from its advisories."""

    id: CveId
    """CVE identifier, e.g. CVE-2022-3602."""
    summary: str
    """Short description from the feed; untrusted data, never instructions."""
    cvss_base_score: float | None = Field(default=None, ge=0, le=10)
    """CVSS base score (0-10), if published."""
    epss_score: float | None = Field(default=None, ge=0, le=1)
    """EPSS probability of exploitation in the next 30 days (0-1), if available."""
    kev_listed: bool = False
    """Whether the CVE is in CISA's Known Exploited Vulnerabilities catalogue."""
    affected_ranges: tuple[AffectedRange, ...] = ()
    """Cited affected ranges extracted from this CVE's advisories."""


class Asset(_Model):
    """A host or service in the lab estate."""

    id: NonBlankStr
    """Stable asset identifier, e.g. a hostname."""
    exposure: Exposure
    """Network reachability; feeds the ranking score."""
    criticality: Criticality
    """Business impact if compromised; feeds the ranking score."""


class Component(_Model):
    """A software package found in an asset's SBOM."""

    name: NonBlankStr
    """Package name as listed in the SBOM."""
    version: NonBlankStr
    """Installed version string, uninterpreted until stage 5."""
    purl: Purl
    """Package URL identifying the package (and usually its version) across ecosystems."""

    @model_validator(mode="after")
    def _purl_version_matches(self) -> Self:
        in_purl = purl_version(self.purl)
        if in_purl is not None and in_purl != self.version:
            raise ValueError(f"purl version {in_purl!r} does not match version {self.version!r}")
        return self


class Finding(_Model):
    """The match result for one component on one asset against one CVE."""

    id: NonBlankStr
    """Stable finding identifier, referenced by proposals."""
    cve_id: CveId
    """The CVE this finding is about."""
    asset_id: NonBlankStr
    """The asset carrying the component."""
    component: Component
    """The SBOM component that was matched."""
    status: FindingStatus
    """Matching verdict."""
    reason: NonBlankStr
    """Human-readable explanation of the verdict."""
    affected_range: AffectedRange | None = None
    """The cited range behind the verdict; required unless status is not_affected."""

    @model_validator(mode="after")
    def _verdict_cites_matching_range(self) -> Self:
        if self.affected_range is None:
            if self.status is not FindingStatus.NOT_AFFECTED:
                raise ValueError(f"a {self.status} finding must cite its affected_range")
            return self
        range_purl = self.affected_range.purl
        if range_purl is not None and purl_package(range_purl) != purl_package(self.component.purl):
            raise ValueError(
                f"affected_range is for {range_purl!r}, not component {self.component.purl!r}"
            )
        return self


class Proposal(_Model):
    """A drafted fix for a finding, delivered as a pull request for human review."""

    id: NonBlankStr
    """Stable proposal identifier, referenced by approvals."""
    finding_id: NonBlankStr
    """The finding this proposal fixes."""
    target_purl: Purl
    """The component at the version the fix moves to."""
    rationale: NonBlankStr
    """Why this target fixes the finding, citing the advisory's fixed version."""
    branch_name: NonBlankStr
    """Branch the fix was pushed to."""
    pr_url: HttpUrl | None = None
    """URL of the opened pull request; None until the PR exists."""


class Approval(_Model):
    """A human reviewer's decision on a proposal."""

    proposal_id: NonBlankStr
    """The proposal being decided."""
    approver: NonBlankStr
    """Identifier of the human reviewer."""
    decision: Decision
    """Approved or rejected."""
    decided_at: AwareDatetime
    """When the decision was made; must be timezone-aware."""
    comment: str | None = None
    """Reviewer's note; required when rejecting."""

    @model_validator(mode="after")
    def _rejection_needs_comment(self) -> Self:
        if self.decision is Decision.REJECTED and not (self.comment and self.comment.strip()):
            raise ValueError("a rejection must include a comment explaining why")
        return self
