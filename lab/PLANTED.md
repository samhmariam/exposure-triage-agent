# Planted vulnerabilities: lab answer key

> **This file is an answer key.** It must move under `evals/answers/` (CLAUDE.md rule 6) before the
> matcher and its evals are built, so the agent cannot read the expected verdicts while matching.
> Until then: do not consult it while working on matching or ranking.

Every CVE here is in the KEV snapshot of 2026-10-28 (`data/raw/kev/2026-10-29.json`). Every
component below was **verified in the generated SBOM** (`lab/sboms/<service>.cdx.json`, Syft 1.18.1,
2026-10-30). Each purl is exactly as Syft reported it. Images are pinned by digest in
`docker-compose.yml`.

This lists **deliberate plants only**. The old base images (Debian 10/11) and the benign services
will also contain ordinary CVEs, and an incidental KEV match is possible. Such a match is not an
error in the matcher, but it is not listed here either.

## Planted

| CVE | Service (image) | Vulnerable component in SBOM | Why affected (CNA record / advisory) | Exploitation conditions | Expected verdict |
|---|---|---|---|---|---|
| CVE-2021-44228 | solr (`solr:8.11.0`) | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` | Affected 2.13.0 up to (not including) 2.15.0, stated only in `changes[]` of the Apache CNA record; Solr 8.11.0 bundles log4j-core 2.14.1 | Attacker-controlled string logged (default Solr config is exploitable) | affected |
| CVE-2021-45046 | solr (`solr:8.11.0`) | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` | CNA: `lessThan: 2.16.0` (start bound is junk: `"Apache Log4j2"`) | Non-default pattern layouts with context lookups | affected |
| CVE-2021-41773 | httpd-legacy (`httpd:2.4.49`) | `pkg:generic/httpd@2.4.49` (binary classifier) | CNA: `"Apache HTTP Server 2.4 2.4.49"` (prose); only 2.4.49 is affected | Path traversal needs files outside the docroot not protected by `Require all denied`; RCE needs mod_cgi | affected |
| CVE-2021-42013 | httpd-legacy (`httpd:2.4.49`) | `pkg:generic/httpd@2.4.49` | CNA: 2.4.49 and 2.4.50 (incomplete fix for 41773) | As above | affected |
| CVE-2020-1938 | tomcat-legacy (`tomcat:9.0.30`) | `pkg:maven/org.apache.tomcat-catalina/catalina@9.0.30` (**Syft's guessed groupId**; the real one is `org.apache.tomcat:tomcat-catalina`) | CNA: `"Apache Tomcat 9.0.0.M1 to 9.0.0.30"` (sic: a typo for 9.0.30); fixed in 9.0.31 | AJP connector on 8009 (enabled by default in 9.0.30, **not published** by our compose) | affected (lower risk: AJP not exposed) |
| CVE-2022-24706 | couchdb (`couchdb:3.2.1`) | `pkg:deb/debian/couchdb@3.2.1-1~bullseye?arch=amd64&distro=debian-11` | CNA: `lessThanOrEqual: 3.2.1` (start bound is junk: `"Apache CouchDB"`) | Erlang distribution port reachable while the default/known cookie is in use (not published by our compose) | affected |
| CVE-2024-23897 | jenkins (`jenkins/jenkins:2.441`) | `pkg:maven/org.jenkins-ci.main/jenkins-core@2.441` (also `args4j@2.33`, the library behind it) | CNA encodes **unaffected** ranges (`versionType: maven`): ≥ 2.442 and 2.426.3+ LTS are fixed, so weekly 2.441 is affected | Built-in CLI enabled (default) | affected |
| CVE-2019-11043 | php-fpm (`php:7.3.10-fpm`) | `pkg:generic/php-fpm@7.3.10` (binary classifier; also `php-cli@7.3.10`) | CNA: 7.3.x up to (not including) 7.3.11 | nginx `fastcgi_split_path_info` with a regex that `\n` can break, passing PATH_INFO to FPM (not in our lab config) | affected (conditional) |

## Controls (fixed versions just past the boundary)

| Service (image) | Component in SBOM | Expected verdict |
|---|---|---|
| httpd-patched (`httpd:2.4.51`) | `pkg:generic/httpd@2.4.51` | **not affected** by CVE-2021-41773 or CVE-2021-42013 |
| solr-patched (`solr:8.11.1`) | `pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0` | **not affected** by CVE-2021-44228 or CVE-2021-45046 |

## Traps

| CVE | Service | Trap | Expected verdict |
|---|---|---|---|
| CVE-2024-4577 (PHP CGI, KEV) | php-fpm | Windows-only (argument injection via a Windows "Best-Fit" character mapping). 7.3 is EOL and absent from the CNA ranges | **not affected** (Linux); must not be inferred from "PHP < 8.1.29" |
| CVE-2025-24813 (Tomcat, KEV) | tomcat-legacy | 9.0.30 is inside the CNA range (9.0.0.M1 to 9.0.98 inclusive), but exploitation needs the default servlet with writes enabled (not the default) | **possibly affected** (version yes, configuration no): flag for review, don't drop |
| CVE-2022-24706 | couchdb | `3.2.1-1~bullseye` vs the CNA's `≤ 3.2.1`: under Debian ordering the package version sorts *above* `3.2.1` (the revision `-1~bullseye` > none). This is a vendor build packaged as a deb, so the bound applies to the **upstream** part `3.2.1` | affected; a naive Debian comparison gives a **false negative** |

## Matching pitfalls seen in these SBOMs

- **Identity:** Syft derives Maven coordinates from JAR manifests and sometimes guesses wrong
  (`org.apache.tomcat-catalina/catalina`). A purl-only match against `org.apache.tomcat/tomcat-catalina`
  would miss Tomcat. Use the CPE (`cpe:2.3:a:apache:tomcat-catalina:9.0.30`) and name as fallbacks.
- **Generic purls:** httpd and PHP are `pkg:generic/...`. No ecosystem comparator applies, so a
  per-product comparator or a review flag is needed.
- **Skipped by the loader (not hidden):** Go's standard library appears as version `go1.23.1` with
  purl `@1.23.1` (grafana ×3, jenkins, postgres, redis). The loader reports these in
  `Sbom.skipped`. Normalising them belongs to a later stage.

## SBOM blind spots

None for these plants: Syft saw every deliberately vulnerable component. A shaded-JAR plant (log4j
classes repackaged inside another JAR, without its own metadata) is a planned follow-up to
exercise a real blind spot.
