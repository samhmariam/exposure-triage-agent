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
