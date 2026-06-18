from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.binary_extractor import BINARY_TEXT_EXTENSIONS
from collectors.file_scanner import SCANNABLE_EXTENSIONS, TEXT_EXTENSIONS, scan_directory
from collectors.smb_scanner import SMBConfig, SMBScanner
from collectors.winrm_endpoint_scanner import _scan_script


FRONTEND_APP = ROOT / "frontend" / "app.js"
PAYLOAD = "dspm_extension_test password=ExtensionSecret123"
CUSTOM_TEST_EXTENSION = ".customrisk"


def frontend_extensions() -> list[str]:
    text = FRONTEND_APP.read_text(encoding="utf-8")
    match = re.search(r"const FILE_EXTENSION_OPTIONS = \[(.*?)\];", text, re.S)
    if not match:
        raise RuntimeError("Could not find FILE_EXTENSION_OPTIONS in frontend/app.js")
    return [
        item[0].lower()
        for item in ast.literal_eval("[" + match.group(1) + "]")
        if isinstance(item, list) and item and str(item[0]).startswith(".")
    ]


def create_zip_xml(path: Path, parts: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in parts.items():
            archive.writestr(name, f"<root><t>{value}</t></root>")


def create_fixture(root: Path, extensions: list[str]) -> None:
    for extension in extensions:
        if extension == ".dockerfile":
            target = root / "Dockerfile"
        else:
            target = root / f"sample{extension}"

        if extension in TEXT_EXTENSIONS:
            target.write_text(f"{PAYLOAD} extension={extension}\n", encoding="utf-8")
        elif extension in BINARY_TEXT_EXTENSIONS:
            if extension in {".docm", ".docx", ".dotm", ".dotx"}:
                create_zip_xml(target, {"word/document.xml": f"{PAYLOAD} extension={extension}"})
            elif extension in {".xlsm", ".xlsx"}:
                create_zip_xml(target, {"xl/sharedStrings.xml": f"{PAYLOAD} extension={extension}"})
            elif extension in {".pptm", ".pptx"}:
                create_zip_xml(target, {"ppt/slides/slide1.xml": f"{PAYLOAD} extension={extension}"})
            elif extension in {".odp", ".ods", ".odt", ".otp"}:
                create_zip_xml(target, {"content.xml": f"{PAYLOAD} extension={extension}"})
            elif extension == ".pdf":
                target.write_bytes(f"%PDF-1.4\n({PAYLOAD} extension={extension})\n%%EOF".encode("latin-1"))
        elif extension == ".zip":
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("metadata.txt", "metadata-only .zip\n")
        else:
            target.write_bytes((f"metadata-only {extension}\n").encode("utf-8"))

    with zipfile.ZipFile(root / "archive_for_entries.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("inside/secret.env", f"{PAYLOAD} extension=.env\n")
        archive.writestr("inside/note.txt", f"{PAYLOAD} extension=.txt\n")


def run_local_filter_checks(root: Path, extensions: list[str]) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    content_failures: list[str] = []
    for extension in extensions:
        records = scan_directory(
            root,
            allowed_extensions=[extension],
            extension_filter_enabled=True,
            include_hidden=True,
            include_system=True,
            max_depth=2,
            inspect_archives=False,
        )
        if not any(record["extension"] == extension for record in records):
            missing.append(extension)
            continue
        if extension in TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS:
            if not any(PAYLOAD in record.get("content", "") for record in records if record["extension"] == extension):
                content_failures.append(extension)
    return missing, content_failures


class FakeSMBEntry:
    def __init__(self, filename: str, size: int):
        self.filename = filename
        self.file_size = size
        self.isDirectory = False
        self.isHidden = False
        self.isSystem = False


class FakeSMBConnection:
    def __init__(self, root: Path, extensions: list[str]):
        self.root = root
        self.entries = []
        for extension in extensions:
            filename = "Dockerfile" if extension == ".dockerfile" else f"sample{extension}"
            target = root / filename
            self.entries.append(FakeSMBEntry(filename, target.stat().st_size))
        archive = root / "archive_for_entries.zip"
        self.entries.append(FakeSMBEntry(archive.name, archive.stat().st_size))

    def listPath(self, share_name: str, folder: str):
        return [FakeSMBEntry(".", 0), FakeSMBEntry("..", 0), *self.entries]

    def retrieveFileFromOffset(self, share_name: str, path: str, buffer, offset: int = 0, max_length: int = 1024 * 256):
        data = (self.root / Path(path).name).read_bytes()[offset : offset + max_length]
        buffer.write(data)


def run_smb_filter_checks(root: Path, extensions: list[str]) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    content_failures: list[str] = []
    for extension in extensions:
        scanner = SMBScanner(
            SMBConfig(
                server="synthetic",
                allowed_extensions=[extension],
                extension_filter_enabled=True,
                include_hidden=True,
                include_system=True,
            )
        )
        scanner.connection = FakeSMBConnection(root, extensions)
        records = scanner._walk_share("share", "/", 0)
        if not any(record["extension"] == extension for record in records):
            missing.append(extension)
            continue
        if extension in TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS:
            if not any(PAYLOAD in record.get("content", "") for record in records if record["extension"] == extension):
                content_failures.append(extension)
    return missing, content_failures


def run_smb_archive_check(root: Path, extensions: list[str]) -> bool:
    scanner = SMBScanner(
        SMBConfig(
            server="synthetic",
            allowed_extensions=[".env"],
            extension_filter_enabled=True,
            include_hidden=True,
            include_system=True,
            inspect_archives=True,
        )
    )
    scanner.connection = FakeSMBConnection(root, extensions)
    records = scanner._walk_share("share", "/", 0)
    return any("archive_for_entries.zip::inside/secret.env" in record["path"] for record in records)


def run_endpoint_script(root: Path, extensions: list[str]) -> dict:
    script = _scan_script(
        paths=[str(root)],
        max_depth=2,
        read_content=True,
        max_read_bytes=1024 * 256,
        allowed_extensions=extensions,
        extension_filter_enabled=True,
        include_hidden=True,
        include_system=True,
        hidden_filter_enabled=False,
        system_filter_enabled=False,
        read_acl=False,
        inspect_archives=True,
    )
    ps1 = root / "_endpoint_scan_check.ps1"
    ps1.write_text(script, encoding="utf-8")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        return json.loads(result.stdout)
    finally:
        ps1.unlink(missing_ok=True)


def main() -> int:
    frontend_defined_extensions = frontend_extensions()
    extensions = sorted(set(frontend_defined_extensions + [CUSTOM_TEST_EXTENSION]))
    missing_backend = sorted(set(frontend_defined_extensions) - SCANNABLE_EXTENSIONS)
    extra_backend = sorted(SCANNABLE_EXTENSIONS - set(frontend_defined_extensions))
    temp_root = ROOT / "data" / "_extension_scan_check"
    shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True, exist_ok=True)
    try:
        create_fixture(temp_root, extensions)
        local_missing, local_content_failures = run_local_filter_checks(temp_root, extensions)
        smb_missing, smb_content_failures = run_smb_filter_checks(temp_root, extensions)
        smb_archive_ok = run_smb_archive_check(temp_root, extensions)
        archive_records = scan_directory(
            temp_root,
            allowed_extensions=[".env"],
            extension_filter_enabled=True,
            include_hidden=True,
            include_system=True,
            max_depth=2,
            inspect_archives=True,
        )
        local_archive_ok = any("archive_for_entries.zip::inside/secret.env" in record["path"] for record in archive_records)

        endpoint = run_endpoint_script(temp_root, extensions)
        endpoint_records = endpoint.get("records", [])
        endpoint_extensions = {record.get("extension") for record in endpoint_records}
        endpoint_missing = sorted(set(extensions) - endpoint_extensions)
        endpoint_content_failures = sorted(
            extension
            for extension in set(extensions) & (TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS)
            if not any(record.get("extension") == extension and PAYLOAD in record.get("content", "") for record in endpoint_records)
        )
        endpoint_archive_ok = any("archive_for_entries.zip::inside/secret.env" in record.get("path", "") for record in endpoint_records)

        result = {
            "frontend_extension_count": len(frontend_defined_extensions),
            "custom_extension_tested": CUSTOM_TEST_EXTENSION,
            "backend_missing_from_frontend": missing_backend,
            "backend_extra_not_in_frontend": extra_backend,
            "local_file_server": {
                "filter_missing": local_missing,
                "content_failures": local_content_failures,
                "archive_entry_filter_ok": local_archive_ok,
            },
            "smb_file_server": {
                "filter_missing": smb_missing,
                "content_failures": smb_content_failures,
                "archive_entry_filter_ok": smb_archive_ok,
            },
            "endpoint_winrm_script": {
                "filter_missing": endpoint_missing,
                "content_failures": endpoint_content_failures,
                "archive_entry_filter_ok": endpoint_archive_ok,
                "diagnostics": endpoint.get("diagnostics", {}),
            },
            "content_capable_extensions": sorted(TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS),
            "metadata_only_extensions": sorted(set(extensions) - (TEXT_EXTENSIONS | BINARY_TEXT_EXTENSIONS)),
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        failed = any(
            [
                missing_backend,
                local_missing,
                local_content_failures,
                smb_missing,
                smb_content_failures,
                not smb_archive_ok,
                not local_archive_ok,
                endpoint_missing,
                endpoint_content_failures,
                not endpoint_archive_ok,
            ]
        )
        return 1 if failed else 0
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
