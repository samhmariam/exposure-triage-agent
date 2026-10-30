.PHONY: sboms

# One CycloneDX SBOM per lab image -> lab/sboms/<service>.cdx.json (Syft runs in Docker).
sboms:
	uv run python lab/gen_sboms.py
