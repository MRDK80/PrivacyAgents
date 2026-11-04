"""Inspect exact archives before clean installation; no runtime activation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

VERSION = "0.1.0a0"
DIST = f"privacy_agents-{VERSION}"
INFO = f"{DIST}.dist-info"
SOURCES = {
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "PROVENANCE.json",
    "MANIFEST.in",
    "src/privacy_agents/__init__.py",
    "src/privacy_agents/cli.py",
    "src/privacy_agents/py.typed",
    "src/privacy_agents/PROVENANCE.json",
    "tools/verify_package.py",
    "tests/test_package.py",
}
WHEEL = {
    "privacy_agents/__init__.py",
    "privacy_agents/cli.py",
    "privacy_agents/py.typed",
    "privacy_agents/PROVENANCE.json",
}
WHEEL |= {
    f"{INFO}/{n}"
    for n in (
        "METADATA",
        "WHEEL",
        "entry_points.txt",
        "top_level.txt",
        "RECORD",
        "licenses/LICENSE",
    )
}
SDIST = SOURCES | {"PKG-INFO", "setup.cfg"}
SDIST |= {
    f"src/privacy_agents.egg-info/{n}"
    for n in (
        "PKG-INFO",
        "SOURCES.txt",
        "dependency_links.txt",
        "entry_points.txt",
        "requires.txt",
        "top_level.txt",
    )
}


REPOSITORY_SOURCES = SOURCES | {
    ".github/CODEOWNERS",
    ".github/pull_request_template.md",
    ".github/workflows/pre-commit.yml",
    ".github/workflows/tests.yml",
    ".gitignore",
    ".pre-commit-config.yaml",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/ARCHITECTURE.md",
    "tools/__init__.py",
    "tools/schema_validate.py",
    "tests/__init__.py",
    "tests/test_schema_generation_type.py",
    "docs/schemas/executor-report.schema.json",
    "docs/schemas/controller-verdict.schema.json",
    "docs/schemas/task-contract.schema.json",
    "tests/test_schema_validate.py",
    "examples/agent-contracts/task.json",
    "examples/agent-contracts/executor-pass.json",
    "examples/agent-contracts/controller-pass.json",
    "examples/agent-contracts/controller-fail.json",
    "docs/ADR-001-generic-binding.md",
    "docs/BINDING_RECORDS.md",
    "docs/BINDING_OPERATIONS.md",
    "tools/binding_codec.py",
    "tests/test_binding_codec.py",
    "tools/mandate_validation.py",
    "tests/test_mandate_validation.py",
    "tools/generic_entry.py",
    "tests/test_generic_entry.py",
    "tools/checkpoint_validation.py",
    "tests/test_checkpoint_validation.py",
    "tools/delivery_validation.py",
    "tests/test_delivery_validation.py",
}


def snapshot_tracked(source: Path, destination: Path) -> None:
    """Copy the closed whole tracked Git checkout; never discover private files."""
    if source.is_symlink() or source.resolve() != source.absolute():
        raise ValueError("Non-canonical repository root")
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=source, text=True
    ).strip()
    if Path(root).resolve() != source:
        raise ValueError("Git checkout root required")
    records = (
        subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=source)
        .decode("utf-8")
        .split("\0")
    )
    names: list[str] = []
    for record in records:
        if not record:
            continue
        header, name = record.split("\t", 1)
        mode, _blob, stage = header.split()
        if mode != "100644" or stage != "0":
            raise ValueError("Non-regular or unmerged index entry")
        names.append(name)
    inventory(names, REPOSITORY_SOURCES)
    # Validate ALL paths and ancestors before copying even the first byte.
    for name in names:
        current = source
        for part in PurePosixPath(name).parts:
            current = current / part
            if current.is_symlink() or current.resolve() != current.absolute():
                raise ValueError("Symlink or escaping source path")
            if current != source / name and not current.is_dir():
                raise ValueError("Non-directory source ancestor")
        if not stat.S_ISREG(current.stat().st_mode):
            raise ValueError("Non-regular source member")
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)


def inventory(names: list[str], expected: set[str]) -> None:
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Unsafe archive path")
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError("Archive inventory mismatch")


def read_sdist(path: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with tarfile.open(path) as archive:
        all_members = archive.getmembers()
        prefix = DIST + "/"
        directories = {DIST}
        for name in SDIST:
            directories.update(
                str(parent)
                for parent in PurePosixPath(prefix + name).parents
                if str(parent) != "."
            )
        seen: set[str] = set()
        for member in all_members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if name in seen:
                raise ValueError("Duplicate archive member")
            seen.add(name)
            if member.isdir() and name not in directories:
                raise ValueError("Unexpected archive directory")
        members = [m for m in all_members if not m.isdir()]
        if any(not m.name.startswith(prefix) for m in members):
            raise ValueError("Unexpected archive root")
        inventory([m.name[len(prefix) :] for m in members], SDIST)
        for member in members:
            if not member.isfile():
                raise ValueError("Non-regular archive member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Missing payload")
            result[member.name[len(prefix) :]] = stream.read()
    return result


def read_wheel(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        inventory(archive.namelist(), WHEEL)
        if any(
            (m.external_attr >> 16) & 0o170000 not in (0, 0o100000)
            for m in archive.infolist()
        ):
            raise ValueError("Non-regular wheel member")
        return {n: archive.read(n) for n in archive.namelist()}


def verify_metadata(payload: bytes) -> None:
    """Require exact single headers, accepting RFC LF and CRLF line endings."""
    message = BytesParser(policy=policy.default).parsebytes(payload)
    expected = {
        "Name": "privacy-agents",
        "Version": VERSION,
        "License-Expression": "MIT",
        "Requires-Python": ">=3.11",
    }
    if message.defects:
        raise ValueError("Malformed distribution metadata")
    for name, value in expected.items():
        if message.get_all(name) != [value]:
            raise ValueError("Distribution metadata mismatch: " + name)


def run(argv: list[str], cwd: Path, env: dict[str, str]) -> str:
    return subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=120, check=True
    ).stdout


def verify(source: Path, temporary: Path) -> dict[str, object]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env["SOURCE_DATE_EPOCH"] = "1767225600"
    wheels: list[Path] = []
    payloads: list[dict[str, bytes]] = []
    for attempt in range(2):
        root = temporary / str(attempt)
        copy, out, unpacked = root / "source", root / "artifacts", root / "unpacked"
        for folder in (out, unpacked):
            folder.mkdir(parents=True)
        snapshot_tracked(source, copy)
        run(
            [
                sys.executable,
                "-c",
                f"import setuptools.build_meta as b; b.build_sdist({str(out)!r})",
            ],
            copy,
            env,
        )
        payload = read_sdist(out / f"{DIST}.tar.gz")
        payloads.append(payload)
        for name, content in payload.items():
            destination = unpacked / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        run(
            [
                sys.executable,
                "-c",
                f"import setuptools.build_meta as b; b.build_wheel({str(out)!r})",
            ],
            unpacked,
            env,
        )
        wheel = out / f"{DIST}-py3-none-any.whl"
        members = read_wheel(wheel)
        assert members[f"{INFO}/licenses/LICENSE"] == (source / "LICENSE").read_bytes()
        assert (
            members["privacy_agents/PROVENANCE.json"]
            == (source / "PROVENANCE.json").read_bytes()
        )
        verify_metadata(members[f"{INFO}/METADATA"])
        assert "privacy_agents.cli:main" in members[f"{INFO}/entry_points.txt"].decode()
        wheels.append(wheel)
    assert payloads[0] == payloads[1], "sdist payload differs"
    assert wheels[0].read_bytes() == wheels[1].read_bytes(), "wheel bytes differ"
    clean = temporary / "clean-env"
    venv.EnvBuilder(with_pip=True).create(clean)
    binary = clean / ("Scripts" if os.name == "nt" else "bin")
    python = binary / ("python.exe" if os.name == "nt" else "python")
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(wheels[0]),
        ],
        temporary,
        env,
    )
    installed = run(
        [
            str(python),
            "-I",
            "-c",
            "import privacy_agents, importlib.metadata as m; "
            "assert privacy_agents.__version__ == m.version('privacy-agents'); "
            "print(privacy_agents.__version__)",
        ],
        temporary,
        env,
    )
    assert installed.strip() == VERSION
    entry = binary / ("privacy-agents.exe" if os.name == "nt" else "privacy-agents")
    assert run([str(entry), "--version"], temporary, env) == VERSION + "\n"
    return {
        "wheel_sha256": hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
        "wheel_byte_reproducible": True,
        "sdist_payload_reproducible": True,
        "clean_install_version": installed.strip(),
    }


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="privacyagents-package-") as folder:
        print(json.dumps(verify(Path(__file__).resolve().parents[1], Path(folder))))
