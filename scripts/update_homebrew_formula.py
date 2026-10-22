"""Point the Homebrew formula at a pytgcli release and its locked runtime deps.

Usage: python3 scripts/update_homebrew_formula.py <version> <formula path>
Run from the tgcli checkout at the release tag, with uv on PATH.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

WHEEL_ONLY = {"telethon"}
SKIPPED_PLATFORMS = ("sys_platform == 'linux'", "sys_platform == 'win32'")


def pypi_release(name: str, version: str) -> dict:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url) as response:  # noqa: S310
        return json.load(response)


def artifact(release: dict, wheel: bool) -> dict:
    if wheel:
        return next(
            u for u in release["urls"] if u["filename"].endswith("-none-any.whl")
        )
    return next(u for u in release["urls"] if u["packagetype"] == "sdist")


def locked_runtime_deps() -> list[tuple[str, str]]:
    exported = subprocess.run(
        ["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--no-emit-project"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    deps = []
    for line in exported.splitlines():
        if not line or line.startswith(("#", " ")):
            continue
        spec, _, marker = line.partition(";")
        if any(platform in marker for platform in SKIPPED_PLATFORMS):
            continue
        name, version = spec.strip().split("==")
        deps.append((name, version))
    return deps


def resource_block(name: str, version: str) -> str:
    release = pypi_release(name, version)
    wheel = name in WHEEL_ONLY
    file = artifact(release, wheel)
    comment = (
        "  # Wheel instead of sdist: telethon >=1.43 sdists cannot build from source\n"
        "  # (hatch_build.py imports telethon_generator, "
        "which is not shipped in the sdist)\n"
        if wheel
        else ""
    )
    display = release["info"]["name"]
    if display.lower() != name:
        display = name
    return (
        f'{comment}  resource "{display}" do\n'
        f'    url "{file["url"]}"\n'
        f'    sha256 "{file["digests"]["sha256"]}"\n'
        "  end\n"
    )


def main(version: str, formula_path: Path) -> None:
    content = formula_path.read_text(encoding="utf-8")

    sdist = artifact(pypi_release("pytgcli", version), wheel=False)
    content, urls = re.subn(
        r'^  url ".*"$', f'  url "{sdist["url"]}"', content, count=1, flags=re.M
    )
    content, shas = re.subn(
        r'^  sha256 ".*"$',
        f'  sha256 "{sdist["digests"]["sha256"]}"',
        content,
        count=1,
        flags=re.M,
    )
    if urls != 1 or shas != 1:
        raise RuntimeError("Failed to patch the formula's top-level url/sha256")

    deps = sorted(locked_runtime_deps(), key=lambda dep: dep[0].lower())
    blocks = "\n".join(resource_block(name, version) for name, version in deps)
    start = re.search(r"^(  # .*\n)*  resource ", content, flags=re.M).start()
    end = content.index("  def install")
    content = content[:start] + blocks + "\n" + content[end:]

    formula_path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
