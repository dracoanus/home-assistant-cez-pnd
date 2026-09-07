"""Pull-request policy checks for the offline Collector service."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MARKDOWN_LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
FORBIDDEN_CONTENT = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "certificate": re.compile("-----BEGIN " + "CERTIFICATE-----"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "JWT": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    ),
    "bearer token value": re.compile(r"Bearer\s+[A-Za-z0-9_-]{43,}"),
    "numeric EAN/ELM value": re.compile(r"(?<!\d)\d{18}(?!\d)"),
    "CEZ credential assignment": re.compile(
        r"(?i)\bCEZ_(?:USERNAME|PASSWORD)\s*[:=]\s*['\"]?[A-Za-z0-9@._+-]{4,}"
    ),
}
FORBIDDEN_SUFFIXES = frozenset({".crt", ".key", ".log", ".p12", ".pem", ".pfx", ".pyc", ".pyo"})
FORBIDDEN_PARTS = frozenset({".pytest_cache", "__pycache__"})


def changed_files(base: str, head: str) -> list[PurePosixPath]:
    """Return added, copied, modified, or renamed paths for one PR."""

    if not SHA_PATTERN.fullmatch(base) or not SHA_PATTERN.fullmatch(head):
        raise ValueError("base and head must be full lowercase commit SHAs")
    output = subprocess.check_output(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            f"{base}...{head}",
        ],
        cwd=ROOT,
    )
    return [PurePosixPath(raw.decode("utf-8")) for raw in output.split(b"\0") if raw]


def validate_path(path: PurePosixPath) -> None:
    """Reject frozen, generated, or private-material paths."""

    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe changed path: {path}")
    if path.parts[:2] == ("poc", "phase2a-runtime"):
        raise ValueError(f"frozen Phase 2A probe changed: {path}")
    if path.parts[:3] == ("collector", "smoke", "runtime"):
        raise ValueError(f"generated smoke runtime changed: {path}")
    if FORBIDDEN_PARTS.intersection(path.parts) or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"generated or private material changed: {path}")


def validate_content(path: PurePosixPath, content: str) -> None:
    """Reject recognizable secret values in changed text files."""

    for label, pattern in FORBIDDEN_CONTENT.items():
        if pattern.search(content):
            raise ValueError(f"{label} detected in {path}")


def validate_markdown_links(path: PurePosixPath, content: str) -> None:
    """Require relative links in changed Markdown to resolve in the checkout."""

    if path.suffix.lower() != ".md":
        return
    source = ROOT.joinpath(*path.parts)
    for target in MARKDOWN_LINK_PATTERN.findall(content):
        target = target.strip().split()[0].strip("<>")
        if target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        relative = target.split("#", 1)[0]
        if relative and not (source.parent / relative).resolve().exists():
            raise ValueError(f"broken relative Markdown link in {path}: {target}")


def validate(base: str, head: str) -> int:
    paths = changed_files(base, head)
    for path in paths:
        validate_path(path)
        source = ROOT.joinpath(*path.parts)
        try:
            content = source.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"non-UTF-8 changed file cannot be inspected: {path}") from error
        validate_content(path, content)
        validate_markdown_links(path, content)
    print(f"PASS: inspected {len(paths)} changed files")
    print("PASS: frozen Phase 2A probe unchanged")
    print("PASS: no generated smoke runtime, private material, or recognizable secrets")
    print("PASS: relative Markdown links resolve")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    arguments = parser.parse_args()
    try:
        return validate(arguments.base, arguments.head)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"FAIL: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
