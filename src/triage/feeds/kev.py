"""CISA Known Exploited Vulnerabilities catalogue."""

from datetime import date
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from triage.http import HttpClient, HttpResponse
from triage.models import CveId

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class _Feed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", use_attribute_docstrings=True)


class KevEntry(_Feed):
    """One catalogue entry: CISA has evidence this CVE was exploited in the wild."""

    cve_id: CveId = Field(alias="cveID")
    """The exploited CVE."""
    vendor_project: str = Field(alias="vendorProject")
    """Vendor as named by CISA (not a package identity)."""
    product: str
    """Product as named by CISA (not a package identity)."""
    vulnerability_name: str = Field(alias="vulnerabilityName")
    """CISA's short title for the vulnerability."""
    date_added: date = Field(alias="dateAdded")
    """When CISA added the CVE to KEV."""
    short_description: str = Field(alias="shortDescription")
    """CISA's description; untrusted data, never instructions."""
    required_action: str = Field(alias="requiredAction")
    """Remediation CISA requires of US federal agencies."""
    due_date: date = Field(alias="dueDate")
    """Federal remediation deadline (BOD 22-01)."""
    known_ransomware_campaign_use: Literal["Known", "Unknown"] = Field(
        alias="knownRansomwareCampaignUse"
    )
    """Whether ransomware campaigns are known to use this CVE."""
    notes: str
    """Free-text notes, usually reference URLs."""
    cwes: tuple[str, ...]
    """CWE identifiers; empty for many entries."""


class KevCatalog(_Feed):
    """The whole catalogue as published at one point in time."""

    title: str
    """Catalogue title."""
    catalog_version: str = Field(alias="catalogVersion")
    """CISA's version label, e.g. 2026.10.28."""
    date_released: AwareDatetime = Field(alias="dateReleased")
    """When CISA published this version."""
    count: int = Field(ge=0)
    """CISA's stated entry count; must equal the number of entries received."""
    vulnerabilities: tuple[KevEntry, ...]
    """All entries."""

    @model_validator(mode="after")
    def _complete_and_unique(self) -> Self:
        if self.count != len(self.vulnerabilities):
            raise ValueError(
                f"count says {self.count} but {len(self.vulnerabilities)} entries were received"
            )
        ids = [v.cve_id for v in self.vulnerabilities]
        if len(set(ids)) != len(ids):
            raise ValueError("catalogue contains duplicate CVE IDs")
        return self


def fetch_kev(client: HttpClient) -> HttpResponse:
    return client.get(KEV_URL)


def parse_kev(text: str) -> KevCatalog:
    return KevCatalog.model_validate_json(text)
