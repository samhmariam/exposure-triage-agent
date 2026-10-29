import json
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from conftest import CVE_IDS
from triage.feeds.cve_records import (
    CVE_API_URL,
    Coverage,
    classify,
    fetch_cve_records,
    parse_cve_record,
)
from triage.http import HttpClient, HttpError


def mutate(text: str, change) -> str:
    data = json.loads(text)
    change(data)
    return json.dumps(data)


def versions(*entries, **product) -> list[dict]:
    """A one-product CNA `affected` list."""
    return [{"vendor": "Acme", "product": "Widget", **product, "versions": list(entries)}]


# --- parsing -------------------------------------------------------------------------------


@pytest.mark.parametrize("cve_id", CVE_IDS)
def test_fixtures_parse(cve_texts, cve_id):
    record = parse_cve_record(cve_texts[cve_id], cve_id)
    assert record.cve_metadata.cve_id == cve_id
    assert record.cve_metadata.state == "PUBLISHED"
    assert record.containers.cna.descriptions
    assert record.containers.cna.affected


def test_log4shell_parts_are_kept_verbatim(cve_texts):
    raw = json.loads(cve_texts["CVE-2021-44228"])["containers"]["cna"]
    cna = parse_cve_record(cve_texts["CVE-2021-44228"], "CVE-2021-44228").containers.cna
    assert list(cna.descriptions) == raw["descriptions"]
    assert list(cna.references) == raw["references"]
    assert list(cna.affected) == raw["affected"]  # including the junk lessThan "log4j-core*"


def test_metadata(cve_texts):
    meta = parse_cve_record(cve_texts["CVE-2024-3400"], "CVE-2024-3400").cve_metadata
    assert meta.assigner_short_name == "palo_alto"
    assert meta.date_updated == datetime(2025, 10, 21, 23, 5, 21, 315000, tzinfo=UTC)


def test_naive_date_updated_is_read_as_utc(cve_texts):
    text = mutate(
        cve_texts["CVE-2024-3400"],
        lambda d: d["cveMetadata"].update(dateUpdated="2017-03-16T00:00:00"),
    )
    meta = parse_cve_record(text, "CVE-2024-3400").cve_metadata
    assert meta.date_updated == datetime(2017, 3, 16, tzinfo=UTC)


def test_record_for_another_cve_is_rejected(cve_texts):
    with pytest.raises(ValueError, match="CVE-2024-3400"):
        parse_cve_record(cve_texts["CVE-2024-3400"], "CVE-2021-44228")


def test_wrong_data_type_is_rejected(cve_texts):
    text = mutate(cve_texts["CVE-2024-3400"], lambda d: d.update(dataType="CVE_LIST"))
    with pytest.raises(ValidationError):
        parse_cve_record(text, "CVE-2024-3400")


def test_unknown_fields_are_ignored(cve_texts):
    text = mutate(cve_texts["CVE-2024-3400"], lambda d: d.update(somethingNew=1))
    assert parse_cve_record(text, "CVE-2024-3400").cve_metadata.cve_id == "CVE-2024-3400"


def test_rejected_record_without_descriptions_parses():
    text = json.dumps(
        {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2020-0001", "state": "REJECTED"},
            "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "Duplicate"}]}},
        }
    )
    record = parse_cve_record(text, "CVE-2020-0001")
    assert record.cve_metadata.state == "REJECTED"
    assert record.containers.cna.affected == ()


# --- fetching ------------------------------------------------------------------------------


def test_fetch_requests_one_api_url_per_id_and_collects_404s(cve_texts):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        cve_id = request.url.path.rsplit("/", 1)[-1]
        if cve_id in cve_texts:
            return httpx.Response(200, text=cve_texts[cve_id])
        return httpx.Response(404, json={"error": "CVE_RECORD_DNE"})

    client = HttpClient(transport=httpx.MockTransport(handler))
    responses, missing = fetch_cve_records(client, ["CVE-2024-3400", "CVE-1999-0001"])
    assert seen == [CVE_API_URL.format(cve_id=i) for i in ("CVE-2024-3400", "CVE-1999-0001")]
    assert [r.text for r in responses] == [cve_texts["CVE-2024-3400"]]
    assert missing == ["CVE-1999-0001"]


def test_fetch_aborts_on_other_errors():
    client = HttpClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(403)), sleep=lambda s: None
    )
    with pytest.raises(HttpError):
        fetch_cve_records(client, ["CVE-2024-3400"])


# --- classification ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cve_id", "expected"),
    [
        ("CVE-2021-44228", Coverage.VERSION_RANGES),  # ranges live in changes[]
        ("CVE-2023-4966", Coverage.VERSION_RANGES),
        ("CVE-2024-3400", Coverage.VERSION_RANGES),
        ("CVE-2026-41709", Coverage.VERSION_RANGES),
        ("CVE-2017-0144", Coverage.PRODUCT_ONLY),  # "version" is a sentence of prose
    ],
)
def test_fixture_coverage(cve_texts, cve_id, expected):
    cna = parse_cve_record(cve_texts[cve_id], cve_id).containers.cna
    assert classify("PUBLISHED", cna.affected) is expected


@pytest.mark.parametrize(
    ("affected", "expected"),
    [
        # a real range, single version, inclusive end
        (versions({"version": "2.0", "lessThan": "2.15.0", "status": "affected"}), "ranges"),
        (versions({"version": "5.4.1", "status": "affected"}), "ranges"),
        (versions({"version": "0", "lessThanOrEqual": "1.2.3", "status": "affected"}), "ranges"),
        # unaffected boundaries + defaultStatus still encode a range
        (
            versions({"version": "2.17.1", "status": "unaffected"}, defaultStatus="affected"),
            "ranges",
        ),
        # range boundaries only in changes[]
        (
            versions(
                {
                    "version": "0",
                    "lessThan": "*",
                    "status": "affected",
                    "changes": [{"at": "3.1", "status": "unaffected"}],
                }
            ),
            "ranges",
        ),
        # placeholders: no usable version
        (versions({"version": "n/a", "status": "affected"}), "product"),
        (versions({"version": "Unspecified", "status": "affected"}), "product"),
        (versions({"version": "0", "lessThan": "*", "status": "affected"}), "product"),
        (versions({"version": "0", "status": "affected"}), "product"),
        (versions({"version": "All", "status": "unaffected"}), "product"),
        (versions({"version": " ", "status": "affected"}), "product"),
        # prose and wildcards stuffed into version fields
        (versions({"version": "versions before 2.3", "status": "affected"}), "product"),
        (versions({"version": "1.0", "lessThan": "log4j-core*", "status": "x"}), "ranges"),
        (versions({"version": "n/a", "lessThan": "log4j-core*", "status": "affected"}), "product"),
        # product identity without versions
        ([{"vendor": "Acme", "product": "Widget"}], "product"),
        ([{"vendor": "Acme", "product": "Widget", "defaultStatus": "affected"}], "product"),
        ([{"collectionURL": "https://pypi.org", "packageName": "widget"}], "product"),
        ([{"vendor": "n/a", "product": "n/a", "cpes": ["cpe:2.3:a:acme:widget:*"]}], "product"),
        # nothing usable
        ([], "nothing"),
        ([{"vendor": "n/a", "product": "n/a", "versions": [{"version": "n/a"}]}], "nothing"),
        ([{"vendor": "Acme"}], "nothing"),
        # malformed shapes from untrusted data never crash the classifier
        (["not an object"], "nothing"),
        ([{"product": 7, "versions": "1.0"}], "nothing"),
        ([{"product": "Widget", "versions": [None, {"version": 1.2}]}], "product"),
    ],
)
def test_classify_edge_cases(affected, expected):
    names = {"ranges": "VERSION_RANGES", "product": "PRODUCT_ONLY", "nothing": "NOTHING"}
    assert classify("PUBLISHED", tuple(affected)) is Coverage[names[expected]]


def test_rejected_record_is_its_own_bucket():
    affected = versions({"version": "1.0", "status": "affected"})
    assert classify("REJECTED", tuple(affected)) is Coverage.REJECTED


def test_missing_record_is_its_own_bucket():
    assert classify(None, None) is Coverage.NO_RECORD
