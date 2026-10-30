# Learning log

Dated notes on what I learned while building the exposure triage agent. Newest first.

Template:

```
## YYYY-MM-DD: <topic>
- What I learned
- What surprised me / what I got wrong
- What I'll do differently
```

---

## 2026-10-30: Lab estate and SBOMs

- Syft saw every planted component, including two that exist only as compiled binaries (httpd,
  php-fpm, as `pkg:generic`). 13 images gave 3,261 components in 7 minutes from the registry.
- "Found" is not "matchable". Syft guessed Tomcat's Maven coordinates
  (`org.apache.tomcat-catalina/catalina`). CouchDB's deb version `3.2.1-1~bullseye` sorts *above*
  the CNA bound `3.2.1` under Debian rules, which would give a false negative. Go stdlib versions
  (`go1.23.1`) disagree with their own purls.
- Verifying each plant in the real SBOM before writing the answer key caught details my plan had
  only assumed (the exact purls and the deb revision).

## 2026-10-30: Ranking signal and enrichment source

- I rank by real-world exploitation first, and I work from CNA records because NVD no longer
  enriches most CVEs.

## 2026-10-29: CVE records for KEV, and how much structure they carry

- Real coverage over all 1,762 KEV CVEs (CNA `affected` only): 845 (48%) have usable version data,
  418 (24%) name a product only, and 499 (28%) carry nothing. All 499 are `vendor: "n/a"`,
  `product: "n/a"`, mostly MITRE-assigned (295), then Microsoft (90) and Adobe (48). No 404s and no
  rejected records.
- "Has a `versions` array" is not "has versions". Log4Shell's real ranges live only in `changes[]`
  (its `lessThan` is `"log4j-core*"`), and Microsoft's CVE-2017-0144 puts a whole sentence in `version`.
  Reusing the `VersionStr` shape check caught both. My plan's example had Log4Shell wrong until I
  looked at the recorded fixture.
- Coverage is classified at report time from stored raw JSON, so tuning the rules costs no re-download.
- DuckDB allows one writer: an open DuckDB UI made a 4.5-minute refresh fail at the very last step.
  The snapshot was already saved, so a re-run reuses it with no network calls.

## 2026-10-29: First feeds (KEV + EPSS)

- Profile the real data before choosing strictness: the live KEV had 175 entries with empty `cwes`,
  which a "non-empty" rule would have rejected.
- Strictness depends on the source. LLM output gets `extra="forbid"`, because unknown keys mean the
  model drifted. Third-party feeds get `extra="ignore"`, because they grow (CISA added `forensicTriage`).
  Required fields stay strict in both.
- Integrity checks that need no domain knowledge are cheap wins: KEV `count` must equal the number of
  entries received (catches truncation), and snapshot `sha256` must match the body (catches edits).
- "Only one module may do X" is enforced by ruff TID251 and a socket-blocking test fixture, not by a
  comment.

## 2026-10-28: Principle: typed contracts at the boundary

- Every model output must parse into typed contracts, so bad output fails at the boundary, not downstream.
- Example (P1): an LLM that dropped `version_start` from "3.0.0 through 3.0.6" would have silently
  produced an open-ended range, flagging every older version with no error anywhere. Now
  `version_start` is a required key, so the output fails validation at extraction.

## 2026-10-28: Property tests found 9 silent acceptances

- Hypothesis, fed LLM-shaped mistakes, found 9 malformed inputs the models accepted. The worst
  were silent defaults: a dropped bound key became an open range, and a dropped inclusive flag
  took its default.
- Fix pattern: make "absent" and "null" mean different things (required-but-nullable fields), so
  the LLM must state "open" on purpose.
- Every tightening needs a matching "still accepts real data" test (Debian epochs, scoped npm,
  purl qualifiers). Otherwise strictness turns into false rejections.

## 2026-10-28: Domain models as a trust boundary

- Models are the first check on LLM output: `extra="forbid"` rejects invented fields, and the
  required `evidence_quote` + `source_url` make "every claim cites evidence" structural.
- A range with no bounds must say `all_versions=True` explicitly, so a dropped bound can't
  silently mean "everything".
- Models deliberately don't check `start <= end`: that needs ecosystem comparators, and a string
  comparison here would be the exact bug the matching stage exists to avoid.

## 2026-10-28: Agent fundamentals and pipeline design

- **The agent loop:** the model proposes tool calls; the harness checks permissions and runs them.
  The model only knows what is in its context window, so it must read before it edits.
- **Context loss:** early chat instructions can be compacted away or diluted. Durable rules go in
  `CLAUDE.md`; rules that must never be broken go in harness permissions/hooks, because a model can
  forget an instruction but cannot get past a deny rule.
- **LLM vs code:** use an LLM for unstructured language (extracting from advisories) and open-ended
  work (drafting fixes). Use deterministic code wherever there is a computable right answer
  (ingest, matching, scoring, verification).
- **A quote existing is not the quote agreeing:** a citation can be genuine while the extracted
  range is wrong ("3.0.0 through 3.0.6" → `< 3.0.7` drops the lower bound). Validation must check
  both.
- **Version comparison is not string comparison:** `1.10` > `1.9`; Debian `1:2.0` > `3.0`;
  `2.0.0rc1` < `2.0.0`. At estate scale, an LLM also silently drops items, causing false negatives.
- **Least privilege for the fix agent:** grant read/edit/test/push-branch/open-PR and registry-only
  network. Deny merge, approve, push to main, CI-config edits, secrets, arbitrary network.
  Advisory text is untrusted input and a prompt-injection vector.
- **Verification:** "Fixed" is a claim. Prove it by rebuilding, regenerating the SBOM (including
  transitive dependencies), re-matching, and checking the *deployed* artifact, not just `main`.
- **What I'll do differently:** after each answer, ask "what's the concrete example?" and "what
  else could go wrong?"
