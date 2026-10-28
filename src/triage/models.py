"""Domain models shared by every pipeline stage.

Pure data shapes: no I/O and no version comparison. Ordering versions needs ecosystem-specific
comparators (stage 5), so these models validate structure only, never `start <= end`.
"""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    model_validator,
)


def _reject_blank(value: str) -> str:
    # Reject without stripping: evidence quotes must stay verbatim for the quote-in-source check.
    if not value.strip():
        raise ValueError("must not be blank")
    return value


NonBlankStr = Annotated[str, Field(min_length=1), AfterValidator(_reject_blank)]
CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
# Shape check only (pkg:<type>/<name>...); full purl parsing belongs to normalisation.
Purl = Annotated[str, Field(pattern=r"^pkg:[a-z][a-z0-9.+-]*/\S+$")]


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
    purl: Purl | None = None
    """Package identity (version-less purl), filled in during normalisation; None until mapped."""
    version_start: str | None = None
    """Lower bound of the range; None means open below. Raw string, compared only by stage 5."""
    version_end: str | None = None
    """Upper bound of the range; None means open above. Raw string, compared only by stage 5."""
    start_inclusive: bool = True
    """Whether `version_start` itself is affected. Ignored when the lower side is open."""
    end_inclusive: bool = False
    """Whether `version_end` itself is affected. Ignored when the upper side is open."""
    all_versions: bool = False
    """Explicit claim that every version is affected; required for a range with no bounds."""
    evidence_quote: NonBlankStr
    """Verbatim advisory text supporting this range; kept unmodified for citation checks."""
    source_url: HttpUrl
    """URL of the advisory the quote was taken from."""

    @model_validator(mode="after")
    def _bounds_match_all_versions(self) -> Self:
        has_bound = self.version_start is not None or self.version_end is not None
        if self.all_versions and has_bound:
            raise ValueError("all_versions=True must not set version_start or version_end")
        if not self.all_versions and not has_bound:
            raise ValueError("a range with no bounds must set all_versions=True explicitly")
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
    """The cited range that produced the verdict; required when status is affected."""

    @model_validator(mode="after")
    def _affected_needs_range(self) -> Self:
        if self.status is FindingStatus.AFFECTED and self.affected_range is None:
            raise ValueError("an affected finding must cite its affected_range")
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
