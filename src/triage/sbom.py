"""CycloneDX SBOMs (as written by Syft) loaded into `Component` models.

Nothing is dropped silently: a component that can't become a valid `Component` is kept in
`Sbom.skipped` with the reason, because a missing component is a potential missed exposure.
"""

from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from triage.models import Component, purl_version


class _Input(BaseModel):
    # External tool output: tolerate new fields, as with feeds.
    model_config = ConfigDict(frozen=True, extra="ignore", use_attribute_docstrings=True)


class CdxComponent(_Input):
    """One CycloneDX component; only the fields matching needs."""

    type: str
    """library, application, operating-system, container, ..."""
    name: str
    """Package name."""
    version: str | None = None
    """Version as the cataloguer found it."""
    purl: str | None = None
    """Package URL; absent for some findings."""
    components: tuple["CdxComponent", ...] = ()
    """Nested components (e.g. JARs inside a WAR)."""


class CdxMetadata(_Input):
    """Document metadata."""

    component: CdxComponent | None = None
    """What the SBOM describes, e.g. the container image."""


class CdxBom(_Input):
    """A CycloneDX JSON document."""

    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    """Always CycloneDX; anything else (e.g. SPDX) is rejected."""
    spec_version: str = Field(alias="specVersion")
    """CycloneDX spec version, e.g. 1.6."""
    metadata: CdxMetadata | None = None
    """Subject and tool information."""
    components: tuple[CdxComponent, ...] = ()
    """Top-level components."""


class _Output(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", use_attribute_docstrings=True)


class OperatingSystem(_Output):
    """The distribution an image is built on; distro-aware matching needs it."""

    name: str
    """Distribution ID, e.g. debian."""
    version: str | None
    """Release, e.g. 12."""


class SkippedComponent(_Output):
    """A component that could not be loaded, kept so the gap stays visible."""

    name: str
    """Name as listed in the SBOM."""
    version: str | None
    """Version as listed, if any."""
    purl: str | None
    """purl as listed, if any."""
    reason: str
    """Why it could not become a Component."""


class Sbom(_Output):
    """One image's SBOM, reduced to what matching needs."""

    source_path: str | None
    """File the SBOM was read from."""
    subject: str | None
    """What the SBOM describes, e.g. httpd:2.4.49."""
    operating_system: OperatingSystem | None
    """Base distribution, if the cataloguer identified one."""
    components: tuple[Component, ...]
    """Loaded components, one per purl."""
    skipped: tuple[SkippedComponent, ...]
    """Components that could not be loaded, with reasons."""


def _flatten(components: Sequence[CdxComponent]) -> Iterator[CdxComponent]:
    for c in components:
        yield c
        yield from _flatten(c.components)


def _subject(metadata: CdxMetadata | None) -> str | None:
    if metadata is None or metadata.component is None:
        return None
    c = metadata.component
    return f"{c.name}:{c.version}" if c.version else c.name


def _to_component(c: CdxComponent) -> Component | str:
    """The Component, or the reason it can't be one."""
    if not c.purl:
        return "no purl"
    version = c.version or purl_version(c.purl)
    if not version:
        return "no version"
    try:
        return Component(name=c.name, version=version, purl=c.purl)
    except ValidationError as exc:
        return "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'component'}: {e['msg']}" for e in exc.errors()
        )


def parse_sbom(text: str, source_path: str | None = None) -> Sbom:
    bom = CdxBom.model_validate_json(text)
    operating_system: OperatingSystem | None = None
    components: dict[str, Component] = {}
    skipped: list[SkippedComponent] = []
    for c in _flatten(bom.components):
        if c.type == "operating-system":
            operating_system = OperatingSystem(name=c.name, version=c.version)
            continue
        result = _to_component(c)
        if isinstance(result, str):
            skipped.append(
                SkippedComponent(name=c.name, version=c.version, purl=c.purl, reason=result)
            )
        else:
            components.setdefault(result.purl, result)
    return Sbom(
        source_path=source_path,
        subject=_subject(bom.metadata),
        operating_system=operating_system,
        components=tuple(components.values()),
        skipped=tuple(skipped),
    )


def load_sbom(path: Path) -> Sbom:
    return parse_sbom(path.read_text(encoding="utf-8"), str(path))
