import json

import pytest
from pydantic import ValidationError

from conftest import FIXTURES
from triage.models import Component
from triage.sbom import OperatingSystem, load_sbom, parse_sbom

HTTPD = FIXTURES / "sbom" / "httpd-2.4.49.cdx.json"


def bom(*components, **extra) -> str:
    """A minimal Syft-shaped CycloneDX document."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"type": "container", "name": "img", "version": "1.0"}},
            "components": list(components),
            **extra,
        }
    )


def lib(name, version, purl, **extra):
    return {"type": "library", "name": name, "version": version, "purl": purl, **extra}


def test_fixture_loads_subject_os_and_components():
    sbom = load_sbom(HTTPD)
    assert sbom.source_path == str(HTTPD)
    assert sbom.subject == "httpd:2.4.49"
    assert sbom.operating_system == OperatingSystem(name="debian", version="10")
    assert [c.name for c in sbom.components] == ["httpd", "adduser", "libssl1.1", "bsdutils"]
    assert sbom.skipped == ()


def test_binary_classifier_finding_is_a_component():
    """httpd is compiled from source: only Syft's binary classifier sees it, as a generic purl."""
    httpd = load_sbom(HTTPD).components[0]
    assert httpd == Component(name="httpd", version="2.4.49", purl="pkg:generic/httpd@2.4.49")


def test_debian_versions_keep_epoch_revision_and_qualifiers():
    by_name = {c.name: c for c in load_sbom(HTTPD).components}
    # The purl percent-encodes '+' (%2B); the version field does not. They still agree.
    assert by_name["libssl1.1"].version == "1.1.1d-0+deb10u7"
    assert by_name["libssl1.1"].purl.startswith("pkg:deb/debian/libssl1.1@1.1.1d-0%2Bdeb10u7?")
    assert "upstream=openssl" in by_name["libssl1.1"].purl
    assert by_name["bsdutils"].version == "1:2.33.1-0.1"


def test_scoped_npm_purl_is_accepted():
    sbom = parse_sbom(bom(lib("@babel/traverse", "7.22.5", "pkg:npm/%40babel/traverse@7.22.5")))
    assert [c.purl for c in sbom.components] == ["pkg:npm/%40babel/traverse@7.22.5"]


def test_nested_components_are_flattened():
    inner = lib("log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    outer = lib("app", "1.0", "pkg:maven/com.example/app@1.0", components=[inner])
    sbom = parse_sbom(bom(outer))
    assert [c.name for c in sbom.components] == ["app", "log4j-core"]


def test_duplicate_purls_are_kept_once():
    twice = lib("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
    assert len(parse_sbom(bom(twice, twice)).components) == 1


def test_missing_version_falls_back_to_the_purl():
    sbom = parse_sbom(bom({"type": "library", "name": "x", "purl": "pkg:pypi/x@1.2"}))
    assert sbom.components[0].version == "1.2"


@pytest.mark.parametrize(
    ("component", "reason"),
    [
        ({"type": "library", "name": "x", "version": "1.0"}, "no purl"),
        ({"type": "library", "name": "x", "purl": "pkg:pypi/x"}, "no version"),
        (lib("x", "1.0", "not-a-purl"), "purl"),
        (lib("x", "1.0", "pkg:pypi/x@2.0"), "does not match"),
        (lib("", "1.0", "pkg:pypi/x@1.0"), "name"),
    ],
)
def test_unusable_components_are_skipped_with_a_reason(component, reason):
    sbom = parse_sbom(bom(component, lib("ok", "1.0", "pkg:pypi/ok@1.0")))
    assert [c.name for c in sbom.components] == ["ok"]
    (skipped,) = sbom.skipped
    assert reason in skipped.reason
    assert skipped.name == component["name"]


def test_operating_system_is_not_reported_as_skipped():
    os_component = {"type": "operating-system", "name": "alpine", "version": "3.20.3"}
    sbom = parse_sbom(bom(os_component))
    assert sbom.operating_system == OperatingSystem(name="alpine", version="3.20.3")
    assert (sbom.components, sbom.skipped) == ((), ())


def test_empty_sbom_is_valid():
    sbom = parse_sbom(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}))
    assert (sbom.subject, sbom.operating_system, sbom.components, sbom.skipped) == (
        None,
        None,
        (),
        (),
    )


def test_unknown_fields_are_ignored():
    sbom = parse_sbom(bom(lib("ok", "1.0", "pkg:pypi/ok@1.0", somethingNew=1), extra=2))
    assert len(sbom.components) == 1


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}),
        json.dumps({"bomFormat": "SPDX", "specVersion": "1.6"}),
        "{not json",
    ],
)
def test_non_cyclonedx_input_is_rejected(text):
    with pytest.raises(ValidationError):
        parse_sbom(text)
