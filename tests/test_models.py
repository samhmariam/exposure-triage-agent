from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ValidationError

from triage.models import (
    AffectedRange,
    Approval,
    Asset,
    Component,
    Cve,
    Decision,
    Finding,
    FindingStatus,
    Proposal,
)

# --- factories: valid kwargs, overridable per test ---


def range_kwargs(**overrides):
    kwargs = {
        "vendor": "OpenSSL Project",
        "product": "OpenSSL",
        "version_start": "3.0.0",
        "version_end": "3.0.6",
        "start_inclusive": True,
        "end_inclusive": True,
        "evidence_quote": "Versions 3.0.0 through 3.0.6 are affected",
        "source_url": "https://www.openssl.org/news/secadv/20221101.txt",
    }
    kwargs.update(overrides)
    return kwargs


def component_kwargs(**overrides):
    kwargs = {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
    kwargs.update(overrides)
    return kwargs


def asset_kwargs(**overrides):
    kwargs = {"id": "lab-web-01", "exposure": "internet_facing", "criticality": "high"}
    kwargs.update(overrides)
    return kwargs


def finding_kwargs(**overrides):
    kwargs = {
        "id": "F-1",
        "cve_id": "CVE-2022-3602",
        "asset_id": "lab-web-01",
        "component": Component(**component_kwargs()),
        "status": "affected",
        "reason": "4.17.20 is inside the cited range",
        "affected_range": AffectedRange(**range_kwargs()),
    }
    kwargs.update(overrides)
    return kwargs


def proposal_kwargs(**overrides):
    kwargs = {
        "id": "P-1",
        "finding_id": "F-1",
        "target_purl": "pkg:npm/lodash@4.17.21",
        "rationale": "Advisory names 4.17.21 as the fixed release",
        "branch_name": "triage/CVE-2021-23337-lodash",
        "pr_url": None,
    }
    kwargs.update(overrides)
    return kwargs


def approval_kwargs(**overrides):
    kwargs = {
        "proposal_id": "P-1",
        "approver": "reviewer-1",
        "decision": "approved",
        "decided_at": datetime(2026, 10, 28, 12, 0, tzinfo=UTC),
        "comment": None,
    }
    kwargs.update(overrides)
    return kwargs


def cve_kwargs(**overrides):
    kwargs = {
        "id": "CVE-2022-3602",
        "summary": "X.509 email address buffer overflow",
        "cvss_base_score": 7.5,
        "epss_score": 0.42,
        "kev_listed": False,
        "affected_ranges": [AffectedRange(**range_kwargs())],
    }
    kwargs.update(overrides)
    return kwargs


# --- missing evidence ---


@pytest.mark.parametrize("field", ["evidence_quote", "source_url"])
def test_affected_range_requires_evidence_fields(field):
    kwargs = range_kwargs()
    del kwargs[field]
    with pytest.raises(ValidationError, match=field):
        AffectedRange(**kwargs)


@pytest.mark.parametrize("quote", ["", "   ", "\n\t"])
def test_affected_range_rejects_blank_evidence_quote(quote):
    with pytest.raises(ValidationError, match="evidence_quote"):
        AffectedRange(**range_kwargs(evidence_quote=quote))


def test_affected_range_rejects_non_url_source():
    with pytest.raises(ValidationError, match="source_url"):
        AffectedRange(**range_kwargs(source_url="not a url"))


def test_evidence_quote_is_kept_verbatim():
    quote = "  Versions 3.0.0 through 3.0.6 are affected "
    assert AffectedRange(**range_kwargs(evidence_quote=quote)).evidence_quote == quote


# --- invalid enums ---


@pytest.mark.parametrize(
    ("model", "kwargs"),
    [
        (Finding, finding_kwargs(status="maybe")),
        (Asset, asset_kwargs(exposure="public")),
        (Asset, asset_kwargs(criticality="severe")),
        (Approval, approval_kwargs(decision="lgtm")),
    ],
)
def test_invalid_enum_values_are_rejected(model, kwargs):
    with pytest.raises(ValidationError):
        model(**kwargs)


def test_enums_accept_their_string_values():
    assert Finding(**finding_kwargs(status="not_affected")).status is FindingStatus.NOT_AFFECTED
    assert Approval(**approval_kwargs()).decision is Decision.APPROVED


# --- open-ended ranges ---


def test_range_open_upper_bound():
    r = AffectedRange(**range_kwargs(version_start="2.0.0", version_end=None))
    assert r.version_start == "2.0.0"
    assert r.version_end is None


def test_range_open_lower_bound():
    r = AffectedRange(**range_kwargs(version_start=None, version_end="4.17.21"))
    assert r.version_start is None
    assert r.version_end == "4.17.21"


def test_range_with_no_bounds_requires_all_versions_flag():
    with pytest.raises(ValidationError, match="all_versions"):
        AffectedRange(**range_kwargs(version_start=None, version_end=None))


def test_range_all_versions_with_no_bounds():
    r = AffectedRange(**range_kwargs(version_start=None, version_end=None, all_versions=True))
    assert r.all_versions


@pytest.mark.parametrize(
    "bounds", [{"version_start": "1.0.0", "version_end": None}, {"version_end": "2.0.0"}]
)
def test_range_all_versions_rejects_bounds(bounds):
    kwargs = range_kwargs(version_start=None, version_end=None, all_versions=True)
    kwargs.update(bounds)
    with pytest.raises(ValidationError, match="all_versions"):
        AffectedRange(**kwargs)


# --- JSON round-trips ---


@pytest.mark.parametrize(
    ("model", "kwargs"),
    [
        (AffectedRange, range_kwargs()),
        (AffectedRange, range_kwargs(version_start=None, version_end=None, all_versions=True)),
        (Cve, cve_kwargs()),
        (Cve, cve_kwargs(cvss_base_score=None, epss_score=None, affected_ranges=[])),
        (Asset, asset_kwargs()),
        (Component, component_kwargs()),
        (Finding, finding_kwargs()),
        (Finding, finding_kwargs(status="not_affected", affected_range=None)),
        (Proposal, proposal_kwargs()),
        (Proposal, proposal_kwargs(pr_url="https://github.com/example/lab/pull/7")),
        (Approval, approval_kwargs()),
        (Approval, approval_kwargs(decision="rejected", comment="Change freeze this week")),
    ],
)
def test_json_round_trip(model: type[BaseModel], kwargs):
    original = model(**kwargs)
    assert model.model_validate_json(original.model_dump_json()) == original


def test_enums_serialise_as_strings():
    assert '"status":"affected"' in Finding(**finding_kwargs()).model_dump_json()


# --- other guards ---


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError, match="extra"):
        AffectedRange(**range_kwargs(confidence="high"))


@pytest.mark.parametrize("purl", ["lodash@4.17.20", "pkg:", "pkg:npm", "pkg:NPM/lodash"])
def test_invalid_purl_is_rejected(purl):
    with pytest.raises(ValidationError, match="purl"):
        Component(**component_kwargs(purl=purl))


@pytest.mark.parametrize("cve_id", ["CVE-22-1", "cve-2022-3602", "2022-3602", "CVE-2022-12"])
def test_invalid_cve_id_is_rejected(cve_id):
    with pytest.raises(ValidationError):
        Cve(**cve_kwargs(id=cve_id))


@pytest.mark.parametrize(
    "overrides",
    [{"cvss_base_score": 10.1}, {"cvss_base_score": -1}, {"epss_score": 1.5}, {"epss_score": -0.1}],
)
def test_scores_out_of_range_are_rejected(overrides):
    with pytest.raises(ValidationError):
        Cve(**cve_kwargs(**overrides))


def test_affected_finding_requires_cited_range():
    with pytest.raises(ValidationError, match="affected_range"):
        Finding(**finding_kwargs(affected_range=None))


def test_rejection_requires_comment():
    with pytest.raises(ValidationError, match="comment"):
        Approval(**approval_kwargs(decision="rejected", comment=None))


def test_naive_decision_time_is_rejected():
    with pytest.raises(ValidationError, match="decided_at"):
        Approval(**approval_kwargs(decided_at=datetime(2026, 10, 28, 12, 0)))


def test_models_are_frozen():
    r = AffectedRange(**range_kwargs())
    with pytest.raises(ValidationError):
        r.version_end = "9.9.9"
