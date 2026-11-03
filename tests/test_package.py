"""Distribution boundary and metadata CLI behavior, using synthetic failures."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "package_verifier", ROOT / "tools/verify_package.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "names",
    [
        ["safe", "safe"],
        ["safe", ".agent-private/payload"],
        ["../safe"],
        ["/safe"],
        ["..\\safe"],
        [],
    ],
)
def test_reject_unexpected_archive_members(names: list[str]) -> None:
    with pytest.raises(ValueError):
        verifier().inventory(names, {"safe"})


@pytest.mark.parametrize(
    "args,code,stdout,stderr",
    [
        (["--version"], 0, "0.1.0a0\n", ""),
        (["--help"], 0, "usage:", ""),
        (["run"], 2, "", "unrecognized arguments"),
    ],
)
def test_cli_stream_contract(
    args: list[str], code: int, stdout: str, stderr: str
) -> None:
    result = subprocess.run(
        [sys.executable, "-c", "from privacy_agents.cli import main; main()", *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == code
    assert stdout in result.stdout if stdout else result.stdout == ""
    assert stderr in result.stderr if stderr else result.stderr == ""


def test_clean_build_install_and_reproducibility(tmp_path: Path) -> None:
    result = verifier().verify(ROOT, tmp_path)
    assert result["clean_install_version"] == "0.1.0a0"


@pytest.mark.parametrize("directory", ["../escape", "/escape", "unexpected"])
def test_reject_actual_tar_directory(tmp_path: Path, directory: str) -> None:
    import io
    import tarfile

    module = verifier()
    archive_path = tmp_path / "synthetic.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for name in module.SDIST:
            member = tarfile.TarInfo(module.DIST + "/" + name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        member = tarfile.TarInfo(directory)
        member.type = tarfile.DIRTYPE
        archive.addfile(member)
    with pytest.raises(ValueError):
        module.read_sdist(archive_path)


@pytest.mark.parametrize("mode", [0o120777, 0o020600, 0o010600, 0o060600])
def test_reject_actual_zip_special_member(tmp_path: Path, mode: int) -> None:
    import zipfile

    module = verifier()
    archive_path = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index, name in enumerate(sorted(module.WHEEL)):
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = (mode if index == 0 else 0o100644) << 16
            archive.writestr(member, b"x")
    with pytest.raises(ValueError):
        module.read_wheel(archive_path)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_metadata_accepts_standard_line_endings(newline: str) -> None:
    payload = newline.join(
        [
            "Metadata-Version: 2.4",
            "Name: privacy-agents",
            "Version: 0.1.0a0",
            "License-Expression: MIT",
            "Requires-Python: >=3.11",
            "",
            "",
        ]
    ).encode()
    verifier().verify_metadata(payload)


@pytest.mark.parametrize(
    "field",
    [
        "Name: privacy-agents",
        "Version: 0.1.0a0",
        "License-Expression: MIT",
        "Requires-Python: >=3.11",
    ],
)
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong"])
def test_metadata_rejects_missing_duplicate_wrong(field: str, mutation: str) -> None:
    fields = [
        "Metadata-Version: 2.4",
        "Name: privacy-agents",
        "Version: 0.1.0a0",
        "License-Expression: MIT",
        "Requires-Python: >=3.11",
    ]
    if mutation == "missing":
        fields.remove(field)
    elif mutation == "duplicate":
        fields.append(field)
    else:
        fields[fields.index(field)] = field.split(":", 1)[0] + ": wrong"
    with pytest.raises(ValueError):
        verifier().verify_metadata(("\r\n".join(fields) + "\r\n\r\n").encode())
