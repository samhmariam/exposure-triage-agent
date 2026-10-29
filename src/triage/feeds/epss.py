"""FIRST EPSS scores: probability of exploitation activity in the next 30 days."""

from collections.abc import Sequence
from datetime import date
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from triage.http import HttpClient, HttpResponse
from triage.models import CveId

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
"""CVEs per request; also the page size, so a full batch always fits on one page."""


class _Feed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", use_attribute_docstrings=True)


class EpssScore(_Feed):
    """One CVE's EPSS score. The API sends numbers as strings; they are parsed to floats."""

    cve: CveId
    """The scored CVE."""
    epss: float = Field(ge=0, le=1)
    """Probability of exploitation activity in the next 30 days."""
    percentile: float = Field(ge=0, le=1)
    """Rank of this score among all scored CVEs."""
    date: date
    """The day the score was computed."""


class EpssPage(_Feed):
    """One API response page."""

    status: Literal["OK"]
    """API status; anything but OK is rejected."""
    total: int = Field(ge=0)
    """Number of matching scores across all pages."""
    offset: int = Field(ge=0)
    """Index of this page's first score."""
    limit: int = Field(ge=1)
    """Page size."""
    data: tuple[EpssScore, ...]
    """Scores on this page. CVEs EPSS doesn't know are simply absent."""

    @model_validator(mode="after")
    def _not_truncated(self) -> Self:
        if self.offset + len(self.data) < self.total:
            raise ValueError(
                f"truncated page: {len(self.data)} scores at offset {self.offset}, "
                f"total {self.total}"
            )
        return self


def batches(ids: Sequence[str], size: int = BATCH_SIZE) -> list[list[str]]:
    return [list(ids[i : i + size]) for i in range(0, len(ids), size)]


def fetch_epss(client: HttpClient, cve_ids: Sequence[str]) -> list[HttpResponse]:
    return [
        client.get(EPSS_URL, params={"cve": ",".join(batch), "limit": BATCH_SIZE})
        for batch in batches(cve_ids)
    ]


def parse_epss(text: str) -> EpssPage:
    return EpssPage.model_validate_json(text)
