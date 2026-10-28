"""Property-based tests: plausible LLM mistakes must not validate.

To record a newly found gap before fixing it, mark its test
`pytest.mark.xfail(strict=True, raises=AssertionError)` and remove the marker with the fix.
"""

from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from triage.models import AffectedRange, Finding

settings.register_profile("triage", deadline=None)
settings.load_profile("triage")

RANGE_FIELDS = set(AffectedRange.model_fields)
FINDING_FIELDS = set(Finding.model_fields)

# --- building blocks ---

int_parts = st.lists(st.integers(0, 99), min_size=1, max_size=3)
versions = int_parts.map(lambda parts: ".".join(map(str, parts)))
names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=15)
quotes = st.text(min_size=1, max_size=80).filter(str.strip)
urls = st.sampled_from(
    [
        "https://www.openssl.org/news/secadv/20221101.txt",
        "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
    ]
)
cve_ids = st.builds(
    lambda year, seq: f"CVE-{year}-{seq:04d}", st.integers(1999, 2030), st.integers(1, 9_999_999)
)
json_values = st.none() | st.booleans() | st.integers() | st.text(max_size=20)


@st.composite
def ordered_versions(draw: st.DrawFn) -> tuple[str, str]:
    """Two versions differing only in the last part, so their order is unambiguous."""
    prefix = draw(st.lists(st.integers(0, 99), max_size=2))
    lo, hi = sorted(draw(st.lists(st.integers(0, 99), min_size=2, max_size=2, unique=True)))
    fmt = lambda last: ".".join(map(str, [*prefix, last]))  # noqa: E731
    return fmt(lo), fmt(hi)


@st.composite
def range_dicts(draw: st.DrawFn, shape: str | None = None) -> dict:
    """A valid AffectedRange as an LLM would emit it (plain JSON-like dict)."""
    shape = shape or draw(st.sampled_from(["both", "start", "end", "all"]))
    d = {
        "vendor": draw(names),
        "product": draw(names),
        "evidence_quote": draw(quotes),
        "source_url": draw(urls),
        "version_start": None,
        "version_end": None,
    }
    if shape == "both":
        d["version_start"], d["version_end"] = draw(ordered_versions())
    elif shape == "start":
        d["version_start"] = draw(versions)
    elif shape == "end":
        d["version_end"] = draw(versions)
    else:
        d["all_versions"] = True
    if d["version_start"] is not None:
        d["start_inclusive"] = draw(st.booleans())
    if d["version_end"] is not None:
        d["end_inclusive"] = draw(st.booleans())
    return d


@st.composite
def finding_dicts(draw: st.DrawFn) -> dict:
    """A valid Finding: component purl agrees with its version; affected verdicts cite a range."""
    name, version = draw(names), draw(versions)
    status = draw(st.sampled_from(["affected", "possibly_affected", "not_affected"]))
    d = {
        "id": f"F-{draw(st.integers(1, 10_000))}",
        "cve_id": draw(cve_ids),
        "asset_id": f"lab-{draw(names)}",
        "component": {"name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"},
        "status": status,
        "reason": draw(quotes),
    }
    if status != "not_affected" or draw(st.booleans()):
        d["affected_range"] = {**draw(range_dicts()), "purl": f"pkg:npm/{name}"}
    return d


placeholder_versions = st.sampled_from(
    ["", " ", "N/A", "n/a", "*", "-", "unknown", "all", "none", "latest", "x"]
) | st.text(alphabet=" \t\n", min_size=1, max_size=3)


@st.composite
def range_expressions(draw: st.DrawFn) -> str:
    """A whole range stuffed into a single bound field."""
    v1, v2 = draw(versions), draw(versions)
    return draw(
        st.sampled_from(
            [
                f"< {v1}",
                f"<={v1}",
                f">= {v1}",
                f"={v1}",
                f"^{v1}",
                f"~{v1}",
                f"{v1} - {v2}",
                f"{v1}, {v2}",
                f"{v1} through {v2}",
                f"before {v1}",
                f"{v1} and later",
            ]
        )
    )


def assert_rejected(model: type, data: dict) -> None:
    try:
        model.model_validate(data)
    except ValidationError:
        return
    raise AssertionError(f"accepted malformed input: {data!r}")


# --- AffectedRange ---


@given(range_dicts())
def test_valid_ranges_validate_and_round_trip(data):
    r = AffectedRange.model_validate(data)
    assert AffectedRange.model_validate_json(r.model_dump_json()) == r


@given(range_dicts(), st.sampled_from(["vendor", "product", "evidence_quote", "source_url"]))
def test_range_missing_required_field_is_rejected(data, field):
    del data[field]
    assert_rejected(AffectedRange, data)


@given(range_dicts(), st.text(alphabet=" \t\n\r", max_size=5))
def test_range_blank_quote_is_rejected(data, blank):
    assert_rejected(AffectedRange, {**data, "evidence_quote": blank})


@given(range_dicts(), st.text(min_size=1, max_size=20).filter(lambda k: k not in RANGE_FIELDS))
def test_range_extra_key_is_rejected(data, key):
    assert_rejected(AffectedRange, {**data, key: "hallucinated"})


@given(
    range_dicts(shape="both"),
    st.sampled_from(["version_start", "version_end"]),
    st.integers() | st.floats(allow_nan=False),
)
def test_number_for_version_is_rejected(data, field, number):
    # Must stay rejected: coercing 1.10 (float) to str gives "1.1", a different version.
    assert_rejected(AffectedRange, {**data, field: number})


@given(
    range_dicts(shape="both"),
    st.sampled_from(["start_inclusive", "end_inclusive", "all_versions"]),
    st.sampled_from(["inclusive", "exclusive", "through", "maybe", "2", "-1", ""]),
)
def test_non_boolean_text_for_flag_is_rejected(data, field, value):
    assert_rejected(AffectedRange, {**data, field: value})


@given(
    range_dicts(shape="both"),
    st.sampled_from(["start_inclusive", "end_inclusive", "all_versions"]),
    st.sampled_from(["true", "false", "yes", "no", "on", "off", "1", "0", "t", "f", 1, 0]),
)
def test_loose_boolean_for_flag_is_rejected(data, field, value):
    assert_rejected(AffectedRange, {**data, field: value})


@given(range_dicts(shape="both"))
def test_swapped_bounds_are_accepted_by_design(data):
    """Models never order versions (rule 4); stage 5 must reject start > end with comparators."""
    swapped = {**data, "version_start": data["version_end"], "version_end": data["version_start"]}
    AffectedRange.model_validate(swapped)


# --- AffectedRange: closed gaps (P1-P8) ---


@given(range_dicts(shape="both"), st.sampled_from(["version_start", "version_end"]))
def test_dropped_bound_key_is_rejected(data, field):
    del data[field]
    assert_rejected(AffectedRange, data)


@given(range_dicts(shape="both"), st.sampled_from(["start_inclusive", "end_inclusive"]))
def test_dropped_inclusive_flag_is_rejected(data, field):
    del data[field]
    assert_rejected(AffectedRange, data)


@given(
    range_dicts(shape="both"),
    st.sampled_from(["version_start", "version_end"]),
    placeholder_versions,
)
def test_placeholder_version_is_rejected(data, field, placeholder):
    assert_rejected(AffectedRange, {**data, field: placeholder})


@given(
    range_dicts(shape="both"),
    st.sampled_from(["version_start", "version_end"]),
    range_expressions(),
)
def test_range_expression_in_bound_is_rejected(data, field, expression):
    assert_rejected(AffectedRange, {**data, field: expression})


@given(range_dicts(shape="both"), versions, st.sampled_from(["start_inclusive", "end_inclusive"]))
def test_empty_range_is_rejected(data, version, exclusive_side):
    data = {**data, "version_start": version, "version_end": version}
    data.update(start_inclusive=True, end_inclusive=True)
    data[exclusive_side] = False
    assert_rejected(AffectedRange, data)


@given(range_dicts(), names, versions)
def test_versioned_purl_on_range_is_rejected(data, name, version):
    assert_rejected(AffectedRange, {**data, "purl": f"pkg:npm/{name}@{version}"})


# --- Finding ---


@given(finding_dicts())
def test_valid_findings_validate_and_round_trip(data):
    f = Finding.model_validate(data)
    assert Finding.model_validate_json(f.model_dump_json()) == f


@given(
    finding_dicts(),
    st.sampled_from(
        ["Affected", "AFFECTED", "vulnerable", "yes", "true", "not affected", "unknown", ""]
    )
    | st.integers(0, 2),
)
def test_status_synonyms_are_rejected(data, status):
    assert_rejected(Finding, {**data, "status": status})


@given(
    finding_dicts(), st.sampled_from(["id", "cve_id", "asset_id", "component", "status", "reason"])
)
def test_finding_missing_required_field_is_rejected(data, field):
    del data[field]
    assert_rejected(Finding, data)


@given(finding_dicts(), st.text(alphabet=" \t\n", max_size=5))
def test_blank_reason_is_rejected(data, blank):
    assert_rejected(Finding, {**data, "reason": blank})


@given(
    finding_dicts(),
    st.text(min_size=1, max_size=20).filter(lambda k: k not in FINDING_FIELDS),
    json_values,
)
def test_finding_extra_key_is_rejected(data, key, value):
    assert_rejected(Finding, {**data, key: value})


@given(finding_dicts(), st.sampled_from(["severity", "fixed_version", "cvss"]))
def test_extra_key_in_nested_component_is_rejected(data, key):
    assert_rejected(Finding, {**data, "component": {**data["component"], key: "x"}})


@given(finding_dicts(), st.integers() | st.floats(allow_nan=False))
def test_number_for_component_version_is_rejected(data, number):
    assert_rejected(Finding, {**data, "component": {**data["component"], "version": number}})


# --- Finding: closed gaps (P1-P8) ---


@given(finding_dicts(), ordered_versions())
def test_component_purl_version_mismatch_is_rejected(data, pair):
    name = data["component"]["name"]
    component = {"name": name, "version": pair[0], "purl": f"pkg:npm/{name}@{pair[1]}"}
    assert_rejected(Finding, {**data, "component": component})


@given(finding_dicts())
def test_possibly_affected_without_range_is_rejected(data):
    data = {**data, "status": "possibly_affected"}
    data.pop("affected_range", None)
    assert_rejected(Finding, data)


@given(finding_dicts().filter(lambda d: "affected_range" in d), names)
def test_range_for_other_package_is_rejected(data, other):
    other_purl = f"pkg:npm/{data['component']['name']}x{other}"
    assert_rejected(
        Finding, {**data, "affected_range": {**data["affected_range"], "purl": other_purl}}
    )
