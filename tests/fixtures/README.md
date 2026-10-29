# Recorded fixtures

Tests never touch the network (`tests/conftest.py` blocks sockets). These files are real responses,
recorded once and trimmed. Edit them only by re-recording, and update this file when you do.

## kev/catalog.json

- Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Recorded: 2026-10-29 (catalogVersion `2026.10.28`, 1762 entries live)
- Trimmed to 5 entries, verbatim and in this order: CVE-2021-44228, CVE-2023-4966, CVE-2017-0144,
  CVE-2024-3400, CVE-2026-41709. `count` changed from 1762 to 5 to match. Re-serialised with
  2-space indentation; all other keys and values unchanged (including the newer `forensicTriage` field).

## epss/page.json

- Source: `https://api.first.org/data/v1/epss?cve=<the 5 CVEs above>&limit=100`
- Recorded: 2026-10-29 (scores dated 2026-10-28)
- **CVE-2017-0144 deliberately removed** and `total` changed from 5 to 4, so the fixtures have
  EPSS coverage of 4/5 and tests exercise a KEV CVE with no score.

## cve/<CVE-ID>.json

- Source: `https://cveawg.mitre.org/api/cve/<CVE-ID>` for each of the 5 KEV fixture CVEs
- Recorded: 2026-10-29, through `triage.http.HttpClient`
- **Verbatim response bodies, not trimmed or edited.** Coverage buckets of the real records: four
  `version_ranges` and one `product_only` (CVE-2017-0144, whose `version` field is a sentence).
  The other buckets (`nothing`, `rejected`, `no_record`) and the injection case are built inside the
  tests from copies, so these files stay real.
- Worth knowing: Log4Shell (CVE-2021-44228) states its ranges in `changes[]`, and its `lessThan`
  is the non-version `"log4j-core*"`.
