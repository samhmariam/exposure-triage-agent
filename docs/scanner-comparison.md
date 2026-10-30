# Scanner comparison: Grype vs the lab's planted CVEs

> **Contains answer-key content.** The tables below restate the expected verdicts from
> `lab/PLANTED.md`. When the answer key moves under `evals/answers/` (ADR 0003), this file must move
> with it, or be reduced to the scanner-only facts.

**Date:** 2026-10-30.

**Scanner:** Grype v0.102.0 (digest-pinned), with default settings and the vulnerability DB built
2026-10-30T06:23Z.

**Input:** the 13 lab SBOMs from Syft 1.18.1.

**Raw results:** [`lab/scanner-baseline/`](../lab/scanner-baseline/), with exact commands in its README.

## Summary

- Grype found **6 of the 8 planted CVEs** and reported **none** of the 4 control CVEs or 2 traps.
- **It had data for all 8.** Both misses were matching problems:
  - **Tomcat:** a package-identity problem.
  - **CouchDB:** the image metadata labels it a Debian distro package, which hides it.
- **Turning on CPE matching for Java recovers Tomcat**, but nearly triples the matches for that image
  (995 → 2,635), which is why it is off by default.

## Planted CVEs

| CVE | Service | Grype | How it matched / why it missed |
|---|---|---|---|
| CVE-2021-44228 | solr | **found** | As `GHSA-jfh8-c2jp-5v3q` (GitHub advisory). Java matcher, exact match on `log4j-core@2.14.1`; fix 2.15.0 |
| CVE-2021-45046 | solr | **found** | As `GHSA-7rjr-3q55-vv33`. Java matcher, exact match; fix 2.16.0 |
| CVE-2021-41773 | httpd-legacy | **found** | NVD CPE match: `pkg:generic/httpd` → `cpe:2.3:a:apache:http_server:2.4.49`. No fix version given |
| CVE-2021-42013 | httpd-legacy | **found** | Same route as CVE-2021-41773 |
| CVE-2020-1938 | tomcat-legacy | **missed** | **Identity and image metadata.** See below |
| CVE-2022-24706 | couchdb | **missed** | **Image metadata, identity and version scheme.** See below |
| CVE-2024-23897 | jenkins | **found** | As `GHSA-6f9g-cxwr-q5jr`. Java matcher on `jenkins-core@2.441`; fix 2.442 |
| CVE-2019-11043 | php-fpm | **found** | NVD CPE match: `cpe:2.3:a:php:php:7.3.10`, reported on both `php-fpm` and `php-cli`; fix 7.3.11 |

## Controls and traps

| CVE | Service | Expected | Grype |
|---|---|---|---|
| CVE-2021-41773, CVE-2021-42013 | httpd-patched (2.4.51) | not affected | not reported ✓ |
| CVE-2021-44228, CVE-2021-45046 | solr-patched (log4j 2.16.0) | not affected | not reported ✓ |
| CVE-2024-4577 (Windows only) | php-fpm | not affected | not reported ✓ |
| CVE-2025-24813 (non-default config) | tomcat-legacy | possibly affected | not reported, for the same reason as Ghostcat (below) |

## Why the misses happened

Categories asked for: no data, different version scheme, image metadata.

### CVE-2020-1938 (Ghostcat), Tomcat 9.0.30: *not* missing data

The DB has the CVE as:
- NVD CPE `cpe:2.3:a:apache:tomcat`, versions `>= 9.0.0, < 9.0.31`
- Debian's `tomcat9` package (`< 9.0.31-1~deb10u1` on Debian 10)

Neither reaches our image, for three reasons:

1. **Image metadata.** Tomcat is unpacked from Apache's tarball into `/usr/local/tomcat`, not
   installed as a Debian package, so the Debian `tomcat9` entries never apply.
2. **Identity.** Syft identified the JARs from their manifests and guessed the Maven coordinates:
   `pkg:maven/org.apache.tomcat-catalina/catalina@9.0.30` instead of
   `org.apache.tomcat:tomcat-catalina`. Grype's Java matcher looks up advisories by these
   coordinates, so it finds nothing.
3. **Configuration.** The NVD CPE route is switched off for Java by default:
   `match.java.using-cpes: false` in `grype config`.

With `GRYPE_MATCH_JAVA_USING_CPES=true` (diagnosis only, not saved in the baseline):
- Grype reports CVE-2020-1938 through other Tomcat JARs (`tomcat-api`, `tomcat-coyote`, …), whose
  generated CPEs include `apache:tomcat:9.0.30`.
- It also reports CVE-2025-24813.
- Total matches for the image rise from 995 to 2,635.

### CVE-2022-24706, CouchDB 3.2.1: *not* missing data

The DB has the CVE as:
- NVD CPE `cpe:2.3:a:apache:couchdb`, `< 3.2.2`
- a Bitnami-namespace entry, which applies only to Bitnami images

The reasons for the miss:

1. **Image metadata.** CouchDB is installed as a `.deb` from **Apache's own apt repository**. Syft
   records it as `pkg:deb/debian/couchdb@3.2.1-1~bullseye?distro=debian-11`, a Debian distro
   package. Grype therefore checks it only against Debian's own advisories. Debian doesn't ship
   CouchDB, so there is nothing there, and there is no CPE fallback for Debian packages (no `dpkg`
   option in `grype config`).
2. **Identity.** Even with a CPE route, Syft's CPE is `cpe:2.3:a:couchdb:couchdb:…`, with vendor
   `couchdb`, not NVD's `apache`.
3. **Version scheme.** The version is `3.2.1-1~bullseye`. Comparing it with NVD's upstream bound
   `< 3.2.2` needs the upstream part `3.2.1`. Under Debian ordering the full string also sorts
   above `3.2.1`, which matters for the CNA's `≤ 3.2.1` bound. (This trap is recorded in PLANTED.md.)

## Other KEV CVEs Grype reported (not planted)

Grype reported these KEV-listed CVEs in images where we planted nothing. They are **unverified**:
not checked against advisories, and not in the answer key.

| Image(s) | KEV CVEs reported |
|---|---|
| most images (HTTP/2 libraries) | CVE-2023-44487 (HTTP/2 Rapid Reset) |
| couchdb, grafana, httpd-patched, solr, solr-patched | CVE-2023-4911 (glibc "Looney Tunables") |
| httpd-legacy, httpd-patched | CVE-2024-38475 (httpd mod_rewrite) |
| jenkins, proxy, solr, solr-patched | CVE-2025-27363 (FreeType) |
| tomcat-legacy | CVE-2020-15999 (FreeType) |
| jenkins | CVE-2025-48384 (git) |
| grafana, jenkins, proxy | CVE-2026-111497 |
| php-fpm | CVE-2026-109618, CVE-2026-109619 |
| worker | none |

These are good candidates for the matcher's evals: each is either a real exposure the answer key
doesn't list, or a scanner false positive. Either way, someone has to look.

## What this means for our matcher

1. **Don't trust the distro label.** `pkg:deb/debian/...` doesn't mean Debian built the package.
   A package with no entry in the distro's advisories should also be checked against upstream
   data, using the upstream part of the version, and flagged when the result is uncertain.
2. **Match identity on several keys.** Use the purl, the CPEs Syft generated, and the name together.
   A Maven groupId that Syft guessed is not an identity.
3. **CPE matching gives coverage at the cost of noise** (Tomcat: 995 → 2,635 matches). Our citation
   rule helps here: a match must cite an advisory range that names this product. That lets us
   widen recall without accepting uncited noise.
4. **Map IDs to their aliases.** Grype reports Java findings under GHSA IDs. A join on CVE ID alone
   would miss Log4Shell, so use `relatedVulnerabilities`.
5. **Baseline to beat:** 6 of 8 planted CVEs, 0 of 6 false positives on controls and traps. Our
   target is 8 of 8 with no new false positives, plus a review flag for the conditional
   CVE-2025-24813.
