import json
from datetime import date

import httpx
import pytest
from pydantic import ValidationError

from triage.feeds.epss import EPSS_URL, fetch_epss, parse_epss
from triage.http import HttpClient


def empty_page(request):
    body = {"status": "OK", "status-code": 200, "total": 0, "offset": 0, "limit": 100, "data": []}
    return httpx.Response(200, json=body)


def mutate(text: str, change) -> str:
    data = json.loads(text)
    change(data)
    return json.dumps(data)


def test_requests_are_batched():
    ids = [f"CVE-2024-{i:05d}" for i in range(250)]
    requests = []

    def handler(request):
        requests.append(request)
        return empty_page(request)

    responses = fetch_epss(HttpClient(transport=httpx.MockTransport(handler)), ids)
    assert len(responses) == 3
    batches = [r.url.params["cve"].split(",") for r in requests]
    assert [len(b) for b in batches] == [100, 100, 50]
    assert [c for b in batches for c in b] == ids
    assert all(r.url.params["limit"] == "100" for r in requests)
    assert all(str(r.url).startswith(EPSS_URL) for r in requests)


def test_no_ids_means_no_requests():
    def handler(request):
        raise AssertionError("no request expected")

    assert fetch_epss(HttpClient(transport=httpx.MockTransport(handler)), []) == []


def test_string_scores_become_floats(epss_text):
    page = parse_epss(epss_text)
    log4shell = next(s for s in page.data if s.cve == "CVE-2021-44228")
    assert log4shell.epss == pytest.approx(0.99999)
    assert isinstance(log4shell.percentile, float)
    assert log4shell.date == date(2026, 10, 28)


def test_unknown_cves_are_absent_not_errors(epss_text):
    # The fixture deliberately omits CVE-2017-0144 (see tests/fixtures/README.md).
    assert "CVE-2017-0144" not in {s.cve for s in parse_epss(epss_text).data}


@pytest.mark.parametrize(
    ("field", "value"), [("epss", "1.5"), ("percentile", "-0.1"), ("epss", "high")]
)
def test_bad_scores_are_rejected(epss_text, field, value):
    with pytest.raises(ValidationError):
        parse_epss(mutate(epss_text, lambda d: d["data"][0].update({field: value})))


def test_non_ok_status_is_rejected(epss_text):
    with pytest.raises(ValidationError):
        parse_epss(mutate(epss_text, lambda d: d.update(status="ERROR")))


def test_truncated_page_is_rejected(epss_text):
    with pytest.raises(ValidationError, match="truncated"):
        parse_epss(mutate(epss_text, lambda d: d.update(total=d["total"] + 1)))
