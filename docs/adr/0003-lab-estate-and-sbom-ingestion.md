# 3. Lab estate and SBOM ingestion

Date: 2026-10-30

## Status

Accepted

## Context

The matcher needs an estate with known answers: services deliberately running KEV-affected
versions, controls just past each fix, and benign services as background. It also needs SBOMs for
those services, loaded into our `Component` model.

## Decision

- **Pin images by tag and digest** (`image:tag@sha256:…`). Official image tags are rebuilt, so a
  tag alone can silently change what we scan, and with it the answer key.
- **Planted services sit behind the compose profile `vulnerable`.** They are genuinely exploitable.
  `docker compose up` starts only the benign ones, and every published port binds to 127.0.0.1.
  SBOM generation never runs containers.
- **Syft runs from its digest-pinned Docker image, reading from the registry** (`registry:` source).
  Nothing is installed locally, the Docker socket is never mounted, and every machine uses the same
  Syft version. `make sboms` calls `lab/gen_sboms.py`, which reads the image list from compose, so
  the list exists in one place.
- **CycloneDX JSON is the SBOM input format.** The loader maps it into `Component`. SPDX can be
  added later as a second parser into the same model; matching never sees the format.
- **Nothing is skipped silently.** A component that can't become a valid `Component` lands in
  `Sbom.skipped` with the validation reason. The OS component is kept as `Sbom.operating_system`
  for distro-aware matching.
- **Every plant is verified in the generated SBOM before it is written into `lab/PLANTED.md`**,
  using the purl exactly as Syft reported it.

## Consequences

- `lab/PLANTED.md` is an answer key. It must move under `evals/answers/` (rule 6) before matcher
  evals exist.
- The SBOMs show identity and comparison problems the matcher must handle (see PLANTED.md, "Matching
  pitfalls"): Syft's guessed Maven coordinates for Tomcat; `pkg:generic` purls for httpd and PHP;
  a vendor deb version (`3.2.1-1~bullseye`) that Debian ordering puts above the CNA bound `3.2.1`;
  Go stdlib versions (`go1.23.1`) that disagree with their purls.
- Generated SBOMs are not committed (`lab/sboms/` is gitignored). They can be regenerated from the
  pinned images and Syft version, though never byte-identically (timestamps, serial numbers).
- The inventory uses `internet|internal` and 1–3. A future loader maps these onto `Exposure` and
  `Criticality`.
