import json
from datetime import date

import httpx
import pytest
from pydantic import ValidationError

from triage.feeds.kev import KEV_URL, fetch_kev, parse_kev
from triage.http import HttpClient


def mutate(text: str, change) -> str:
    data = json.loads(text)
    change(data)
    return json.dumps(data)


def test_fixture_parses(kev_text):
    catalog = parse_kev(kev_text)
    assert catalog.catalog_version == "2026.10.28"
    assert catalog.count == len(catalog.vulnerabilities) == 5


def test_log4shell_fields(kev_text):
    entry = next(v for v in parse_kev(kev_text).vulnerabilities if v.cve_id == "CVE-2021-44228")
    assert (entry.vendor_project, entry.product) == ("Apache", "Log4j2")
    assert entry.date_added == date(2021, 12, 10)
    assert entry.due_date == date(2021, 12, 24)
    assert entry.known_ransomware_campaign_use == "Known"
    assert "CWE-20" in entry.cwes


@pytest.mark.parametrize("field", ["cveID", "dateAdded", "dueDate", "knownRansomwareCampaignUse"])
def test_missing_required_field_is_rejected(kev_text, field):
    with pytest.raises(ValidationError):
        parse_kev(mutate(kev_text, lambda d: d["vulnerabilities"][0].pop(field)))


def test_unknown_field_is_ignored(kev_text):
    """Feeds grow by adding fields (forensicTriage was one); additions must not break refresh."""
    changed = mutate(kev_text, lambda d: d["vulnerabilities"][0].update(brandNewField="x"))
    assert parse_kev(changed).count == 5


def test_empty_cwes_are_accepted(kev_text):
    # 175 live entries have no CWE.
    changed = mutate(kev_text, lambda d: d["vulnerabilities"][0].update(cwes=[]))
    assert parse_kev(changed).vulnerabilities[0].cwes == ()


def test_count_mismatch_is_rejected(kev_text):
    with pytest.raises(ValidationError, match="count"):
        parse_kev(mutate(kev_text, lambda d: d.update(count=6)))


def test_duplicate_cve_is_rejected(kev_text):
    def duplicate(d):
        d["vulnerabilities"].append(d["vulnerabilities"][0])
        d["count"] += 1

    with pytest.raises(ValidationError, match="duplicate"):
        parse_kev(mutate(kev_text, duplicate))


@pytest.mark.parametrize(
    ("field", "value"), [("knownRansomwareCampaignUse", "Maybe"), ("dueDate", "soon")]
)
def test_bad_values_are_rejected(kev_text, field, value):
    with pytest.raises(ValidationError):
        parse_kev(mutate(kev_text, lambda d: d["vulnerabilities"][0].update({field: value})))


def test_fetch_kev_goes_through_http_client(kev_text):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, text=kev_text)

    resp = fetch_kev(HttpClient(transport=httpx.MockTransport(handler)))
    assert seen == [KEV_URL]
    assert resp.text == kev_text
