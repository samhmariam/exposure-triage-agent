"""Write one CycloneDX SBOM per lab image to lab/sboms/<service>.cdx.json.

Syft runs from its pinned Docker image and reads each image straight from the registry, so
nothing is installed locally, no container is started, and the Docker socket is never mounted.
The image list comes from docker-compose.yml itself (all profiles), so it lives in one place.

    uv run python lab/gen_sboms.py [service ...]     (or: make sboms)
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

LAB = Path(__file__).parent
COMPOSE = LAB / "docker-compose.yml"
OUT = LAB / "sboms"
SYFT = (
    "anchore/syft:v1.18.1@sha256:b8c170b8e51bfc4779ec3ef4399942c57290f5ce76a9c3af564c9d00d4946a6b"
)
PLATFORM = "linux/amd64"


def _run(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])} … failed:\n{result.stderr.strip()}")
    return result.stdout


def service_images() -> dict[str, str]:
    """service name -> pinned image reference, for every profile."""
    config = json.loads(
        _run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE),
                "--profile",
                "*",
                "config",
                "--format",
                "json",
            ]
        )
    )
    images = {name: svc["image"] for name, svc in config["services"].items()}
    unpinned = [name for name, image in images.items() if "@sha256:" not in image]
    if unpinned:
        raise RuntimeError(f"images must be pinned by digest: {', '.join(sorted(unpinned))}")
    return dict(sorted(images.items()))


def generate(service: str, image: str) -> int:
    sbom = _run(
        [
            "docker", "run", "--rm", SYFT,
            f"registry:{image}", "--platform", PLATFORM, "-o", "cyclonedx-json", "-q",
        ]
    )  # fmt: skip
    components = len(json.loads(sbom).get("components", []))
    path = OUT / f"{service}.cdx.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(sbom, encoding="utf-8")
    os.replace(tmp, path)
    return components


def main(argv: list[str]) -> int:
    try:
        images = service_images()
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    wanted = argv or list(images)
    unknown = sorted(set(wanted) - set(images))
    if unknown:
        print(f"error: unknown service(s): {', '.join(unknown)}", file=sys.stderr)
        return 1
    OUT.mkdir(exist_ok=True)
    for service in wanted:
        start = time.monotonic()
        try:
            count = generate(service, images[service])
        except RuntimeError as exc:
            print(f"error: {service}: {exc}", file=sys.stderr)
            return 1
        print(f"{service:<15} {count:>5} components  {time.monotonic() - start:6.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
