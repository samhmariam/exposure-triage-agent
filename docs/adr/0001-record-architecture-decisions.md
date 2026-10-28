# 1. Record architecture decisions

Date: 2026-10-28

## Status

Accepted

## Context

This project draws hard lines between what an LLM may do and what deterministic code must do, and
between which pipeline stages may write and which may not. These trust-boundary decisions will be
revisited as the system grows, and both humans and coding agents need to know why each line sits
where it does. Decisions that live only in chat history or commit messages get lost.

## Decision

We will record significant architecture decisions as Architecture Decision Records (ADRs), as
described by Michael Nygard, in `docs/adr/`.

- Files are numbered sequentially: `NNNN-short-title.md`.
- Each ADR has the sections Status, Context, Decision, and Consequences.
- An accepted ADR is not rewritten. To change a decision, write a new ADR that supersedes it and
  update the old one's status to "Superseded by NNNN".

## Consequences

- The reasoning behind trust boundaries (e.g. "matching is deterministic code") is discoverable
  next to the code, by people and by agents reading the repo.
- Writing an ADR adds a small cost to each significant change; that is intended.
- `CLAUDE.md` states the rules; ADRs explain why. If they disagree, fix one of them in the same change.
