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

## 2026-10-30: Confidence intervals for a proportion, and sizing an eval

- **Use the Wilson interval** for accuracy, recall and similar proportions (k correct out of n),
  with z = 1.96 for 95%:

  ```
  p = k / n
  center = (p + z²/2n) / (1 + z²/n)
  margin = z · √( p(1−p)/n + z²/4n² ) / (1 + z²/n)
  CI     = [center − margin, center + margin]
  ```

  The simpler Wald interval, p ± z·√(p(1−p)/n), breaks at small n and near 0% or 100%. For 6/8 it
  gives [45%, 105%], and for 0/50 it gives [0%, 0%].
- **Worked examples** (checked in Python):

  | Result | Wilson 95% CI | Width |
  |---|---|---|
  | 40/50 (80%) | [67.0%, 88.8%] | 21.8 pts |
  | 120/150 (80%) | [72.9%, 85.6%] | 12.7 pts |
  | 45/50 (90%) | [78.6%, 95.7%] | 17.0 pts |
  | 6/8 (Grype on the lab plants) | [40.9%, 92.9%] | 51.9 pts |
  | 0/50 (no misses) | [0.0%, 7.1%] | 7.1 pts |

- **Width shrinks with 1/√n.** 3× the data makes the interval about 1.73× narrower (21.8 → 12.7).
  Halving the width takes 4× the data.
- **Sample size for a target margin E**, from the normal approximation. Round up, and use a pessimistic p:

  ```
  n ≈ z² · p(1−p) / E²
  ```

  | Expected p | Margin E | n needed |
  |---|---|---|
  | 0.90 | ±5 pts | 139 |
  | 0.80 | ±5 pts | 246 |
  | 0.50 (worst case) | ±5 pts | 385 |
  | 0.90 | ±2.5 pts | 554 |

  If p is unknown, use 0.5, which gives the largest n. Halving E quadruples n.
- **Claiming a target means checking the lower bound.** 45/50 = 90% does *not* show "above 85%",
  because the lower bound is 78.6%. To show it, the lower bound must clear 85%: plan for somewhat
  more than the n above, and state targets in terms of the lower bound.
- **Zero failures isn't zero risk.** With 0 misses in n, the 95% upper bound is about 3/n (the "rule
  of three"): 6% for n = 50 (Wilson gives 7.1%). "No missed exposures in 50 cases" still allows a
  miss rate of a few percent.
- **What this means for our evals:** the 8 lab plants are test cases that show *which* failures
  happen and why. They can't measure a rate. Per-stratum results need their own intervals: a
  stratum of about 42 items has a margin of about ±13 points.

## 2026-10-30: Claude Code hooks

- PreToolUse blocks (exit 2, stderr goes back to Claude); PostToolUse can't undo anything but feeds
  back failures. That's enough to make "lint and test after every edit" happen automatically: the hook
  caught over-long lines in its own test file before I'd run anything.
- My first protection hook **silently allowed** the edit it was meant to block. On Windows
  `os.path.normcase` turns `/` into `\`, so `"lab/PLANTED.md"` never matched. A guard that fails
  open looks exactly like a guard that works until you try to get past it. Every guard now has
  tests, including a case that must be blocked.
- Hooks load from a snapshot. The first test edit went through before the new hooks were active, so
  demonstrate a guard *after* confirming it's live.
- The Bash guard is textual. It blocks accidents (`sed -i`, `cat evals/answers/...`) but not
  deliberate obfuscation; the sha256 check on snapshots and a human-owned answer key remain the
  backstops.

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
