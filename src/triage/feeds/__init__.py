"""Stage 1 ingest feeds. Fetching goes through triage.http; parsing is pure.

Feed models use extra="ignore", unlike the LLM-boundary models in triage.models: these are
structured third-party feeds that grow by adding fields, so additions must not break a refresh.
Missing or malformed required fields still fail validation.
"""
