from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import subprocess
import tempfile
import zipfile
from datetime import date, timedelta
from pathlib import Path


COMPANY = "Caspian Retail Group"
DOMAIN = "caspian-retail.example"
RANDOM = random.Random(42)

DEPARTMENTS = {
    "Finance": ["AccountsPayable", "Treasury", "Audit", "Tax"],
    "HR": ["Payroll", "Recruiting", "EmployeeRelations", "Benefits"],
    "Legal": ["Contracts", "Board", "Compliance"],
    "IT": ["Identity", "Cloud", "Database", "Backups", "ServiceDesk"],
    "Sales": ["Enterprise", "Partners", "CustomerExports"],
    "Engineering": ["Platform", "Data", "Release", "DevOps"],
    "Operations": ["Stores", "Logistics", "Facilities"],
    "Executive": ["Strategy", "M&A", "BoardPackets"],
    "Public": ["Templates", "Training", "Announcements"],
}

FIRST_NAMES = [
    "Aysel",
    "Leyla",
    "Nigar",
    "Farid",
    "Kamran",
    "Murad",
    "Sabina",
    "Rauf",
    "Elvin",
    "Gunel",
    "Tural",
    "Samir",
]

LAST_NAMES = [
    "Aliyev",
    "Hasanov",
    "Mammadova",
    "Karimov",
    "Huseynli",
    "Quliyev",
    "Rahimova",
    "Ismayilov",
    "Safarli",
    "Jafarova",
]

CONFIDENTIAL_LABELS = [
    "CONFIDENTIAL",
    "Internal use only",
    "Restricted",
    "Secret",
]


def person(index: int) -> dict[str, str]:
    first = FIRST_NAMES[index % len(FIRST_NAMES)]
    last = LAST_NAMES[(index * 3) % len(LAST_NAMES)]
    username = f"{first.lower()}.{last.lower()}"
    fin = f"{RANDOM.choice('ABCDEFGHJKLMNPQRSTUVWXYZ')}{RANDOM.randint(100000, 999999)}"
    phone_prefix = RANDOM.choice(["50", "51", "55", "70", "77", "99", "10", "12"])
    return {
        "name": f"{first} {last}",
        "email": f"{username}@{DOMAIN}",
        "phone": f"+994 {phone_prefix} {RANDOM.randint(100,999)} {RANDOM.randint(10,99)} {RANDOM.randint(10,99)}",
        "fin": fin,
        "employee_id": f"CRG-{10000 + index}",
    }


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def set_windows_attributes(path: Path, *flags: str) -> None:
    if not flags:
        return
    attrib = shutil.which("attrib")
    if not attrib:
        return
    try:
        subprocess.run(
            [attrib, *flags, str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_docx(path: Path, paragraphs: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"<w:p><w:r><w:t>{escape_xml(text)}</w:t></w:r></w:p>" for text in paragraphs)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        archive.writestr("word/document.xml", f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>')


def write_xlsx(path: Path, rows: list[list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for col_index, value in enumerate(row, start=1):
            ref = f"{chr(64 + col_index)}{row_index}"
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape_xml(str(value))}</t></is></c>')
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    sheet_xml = f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        archive.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')


def write_pptx(path: Path, slides: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        for index, text in enumerate(slides, start=1):
            archive.writestr(
                f"ppt/slides/slide{index}.xml",
                f'<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:r><a:t>{escape_xml(text)}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>',
            )


def write_password_protected_zip(path: Path, inner_name: str, content: str, password: str = "DSPM-Test-2026!") -> bool:
    """Create a synthetic password-protected ZIP when the system zip utility is available.

    Python's stdlib can read encrypted ZIP metadata but cannot create encrypted ZIPs,
    so this helper uses the platform zip command and falls back safely when unavailable.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    zip_binary = shutil.which("zip")
    if not zip_binary:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(inner_name, content)
        return False
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        inner_path = temp_root / inner_name
        inner_path.write_text(content.strip() + "\n", encoding="utf-8")
        subprocess.run(
            [zip_binary, "-j", "-P", password, str(path), str(inner_path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return True



def escape_xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def card_number(index: int) -> str:
    test_cards = ["4111 1111 1111 1111", "5555 5555 5555 4444", "4000 0000 0000 0002"]
    return test_cards[index % len(test_cards)]


def iban(index: int) -> str:
    return f"AZ21NABZ0000000013701000{index:04d}"


def secret_block(index: int) -> str:
    return f"""
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC synthetic-key-{index:04d}
line1line2line3line4line5line6line7line8line9line10
-----END PRIVATE KEY-----
aws_access_key=AKIA{index:04d}SYNTHETICKEY{index % 10}
api_key=crg_live_{index:04d}_SYNTHETIC_TOKEN_VALUE
password=Winter2026!{index:03d}
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.syntheticpayload{index:04d}.syntheticsignature{index:04d}
"""


def generate(root: Path, files_per_department: int) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    people = [person(index) for index in range(180)]
    created_files: list[dict[str, object]] = []

    write_text(
        root / "README_enterprise_dataset.md",
        f"""
# {COMPANY} synthetic file-server dataset

This folder is generated for DSPM testing. All names, credentials, payment cards,
IBANs, FIN values, tokens, and business records are fake and intentionally placed
to exercise detection logic.
""",
    )

    for dept_index, (department, shares) in enumerate(DEPARTMENTS.items()):
        for share_index, share in enumerate(shares):
            share_root = root / department / share
            write_text(
                share_root / "00_share_notice.txt",
                f"{COMPANY} {department}/{share}. Owner: {department.lower()}-owner@{DOMAIN}. Classification: Internal use only.",
            )
            for file_index in range(files_per_department):
                absolute_index = dept_index * 1000 + share_index * 100 + file_index
                target = share_root / folder_for(file_index)
                label = RANDOM.choice(CONFIDENTIAL_LABELS)
                profile = people[absolute_index % len(people)]
                extension = choose_extension(department, file_index)
                filename = choose_filename(department, share, file_index, extension)
                path = target / filename
                content = build_content(department, share, file_index, absolute_index, profile, label)
                write_by_extension(path, content, department, share, absolute_index, profile)
                created_files.append({"path": str(path.relative_to(root)), "department": department, "share": share, "extension": extension})

    add_cross_department_exports(root, people, created_files)
    add_protected_content_samples(root, created_files)
    add_hidden_and_system_samples(root, created_files)
    write_text(root / "_manifest.json", json.dumps({"company": COMPANY, "file_count": len(created_files), "generated": date.today().isoformat(), "files": created_files[:75]}, indent=2))


def folder_for(index: int) -> Path:
    year = 2023 + (index % 4)
    quarter = f"Q{(index % 4) + 1}"
    return Path(str(year)) / quarter if index % 3 else Path("Current")


def choose_extension(department: str, index: int) -> str:
    if department == "IT":
        return RANDOM.choice([".env", ".json", ".cfg", ".sql", ".log", ".ps1", ".pem", ".bak"])
    if department == "Engineering":
        return RANDOM.choice([".py", ".js", ".yaml", ".md", ".log", ".json"])
    if department in {"Finance", "HR", "Sales"}:
        return RANDOM.choice([".csv", ".xlsx", ".docx", ".txt", ".json"])
    if department in {"Legal", "Executive"}:
        return RANDOM.choice([".docx", ".pdf", ".md", ".txt"])
    return RANDOM.choice([".txt", ".csv", ".docx", ".json", ".log"])


def choose_filename(department: str, share: str, index: int, extension: str) -> str:
    risky_names = {
        "Finance": ["customer_payment_export", "bank_iban_register", "invoice_recon", "tax_confidential"],
        "HR": ["payroll_salary_export", "employee_fin_list", "benefits_confidential", "recruiting_candidates"],
        "Legal": ["contract_restricted", "nda_customer", "board_secret", "litigation_confidential"],
        "IT": ["prod_passwords", "database_backup", "vpn_credentials", "cloud_admin_token"],
        "Sales": ["customer_contacts", "partner_contract", "enterprise_pipeline", "customer_export"],
        "Engineering": ["release_secret", "api_token_notes", "database_migration", "incident_log"],
        "Executive": ["ma_secret", "board_packet_confidential", "strategy_restricted", "investor_contacts"],
    }
    clean_names = ["meeting_notes", "project_plan", "training_roster", "process_overview", "status_report"]
    names = risky_names.get(department, clean_names)
    base = names[index % len(names)] if index % 2 == 0 else clean_names[index % len(clean_names)]
    return f"{base}_{share.lower()}_{index:03d}{extension}"


def build_content(department: str, share: str, index: int, absolute_index: int, profile: dict[str, str], label: str) -> str:
    lines = [
        f"{label} - {COMPANY}",
        f"Department: {department}",
        f"Share: {share}",
        f"Record owner: {profile['name']} <{profile['email']}>",
        f"Review date: {date(2026, 1, 1) + timedelta(days=index * 7)}",
    ]
    if department in {"HR", "Finance", "Sales", "Executive"} or index % 4 == 0:
        lines.extend(
            [
                f"Employee/customer phone: {profile['phone']}",
                f"FIN: {profile['fin']}",
                f"Payment card for synthetic test: {card_number(absolute_index)}",
                f"Settlement IBAN: {iban(absolute_index)}",
            ]
        )
    if department in {"IT", "Engineering"} or index % 9 == 0:
        lines.append(secret_block(absolute_index))
        lines.append(f"server=db-{share.lower()}-{index};user=svc_{share.lower()};password=ChangeMe{index}!;database=enterprise_dw;encrypt=true;")
    if index % 5 == 0:
        lines.append("Notes: restricted export copied from shared drive for remediation testing.")
    return "\n".join(lines)


def write_by_extension(path: Path, content: str, department: str, share: str, index: int, profile: dict[str, str]) -> None:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        rows = [
            {
                "department": department,
                "share": share,
                "name": person(index + offset)["name"],
                "email": person(index + offset)["email"],
                "phone": person(index + offset)["phone"],
                "fin": person(index + offset)["fin"],
                "iban": iban(index + offset),
                "card": card_number(index + offset),
                "classification": "CONFIDENTIAL" if offset % 2 == 0 else "Internal use only",
            }
            for offset in range(6)
        ]
        write_csv(path, rows)
    elif suffix == ".json":
        write_text(path, json.dumps({"classification": "restricted", "owner": profile, "notes": content.splitlines(), "api_key": f"json_SECRET_{index:04d}_SYNTHETIC"}, indent=2))
    elif suffix == ".docx":
        write_docx(path, content.splitlines())
    elif suffix == ".xlsx":
        rows = [["Name", "Email", "Phone", "FIN", "IBAN", "Card", "Classification"]]
        rows.extend([[person(index + offset)["name"], person(index + offset)["email"], person(index + offset)["phone"], person(index + offset)["fin"], iban(index + offset), card_number(index + offset), "CONFIDENTIAL"] for offset in range(8)])
        write_xlsx(path, rows)
    elif suffix == ".pptx":
        write_pptx(path, content.splitlines()[:5])
    elif suffix == ".pdf":
        write_text(path, f"%PDF-1.3\n1 0 obj <<>> stream\n({content})\nendstream\nendobj\n%%EOF")
    else:
        write_text(path, content)


def add_cross_department_exports(root: Path, people: list[dict[str, str]], created_files: list[dict[str, object]]) -> None:
    rows = []
    for index, profile in enumerate(people[:75]):
        rows.append(
            {
                "customer_id": f"CUST-{50000 + index}",
                "name": profile["name"],
                "email": profile["email"],
                "phone": profile["phone"],
                "fin": profile["fin"],
                "iban": iban(index),
                "payment_card": card_number(index),
                "account_manager": person(index + 22)["email"],
            }
        )
    export_path = root / "Shared" / "CustomerExports" / "2026" / "customer_master_export_confidential.csv"
    write_csv(export_path, rows)
    created_files.append({"path": str(export_path.relative_to(root)), "department": "Shared", "share": "CustomerExports", "extension": ".csv"})

    vault_path = root / "IT" / "Cloud" / "Current" / "breakglass_admin_credentials.env"
    write_text(vault_path, secret_block(9999) + "\nroot_email=cloud-admin@caspian-retail.example\n")
    created_files.append({"path": str(vault_path.relative_to(root)), "department": "IT", "share": "Cloud", "extension": ".env"})


def add_protected_content_samples(root: Path, created_files: list[dict[str, object]]) -> None:
    secure_root = root / "Executive" / "BoardPackets" / "Secure"
    protected_zip = secure_root / "password_protected_board_pack.zip"
    encrypted = write_password_protected_zip(
        protected_zip,
        "board_packet_private_notes.txt",
        "CONFIDENTIAL board notes with synthetic payment card 4111 1111 1111 1111 and break-glass password placeholder.",
    )
    created_files.append({
        "path": str(protected_zip.relative_to(root)),
        "department": "Executive",
        "share": "BoardPackets",
        "extension": ".zip",
        "protected": encrypted,
    })

    vault_path = root / "IT" / "Backups" / "Secure" / "production_credential_vault.kdbx"
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_bytes(b"KDBX_SYNTHETIC_PROTECTED_VAULT\x00\x01DSPM_TEST")
    created_files.append({
        "path": str(vault_path.relative_to(root)),
        "department": "IT",
        "share": "Backups",
        "extension": ".kdbx",
        "protected": True,
    })


def add_hidden_and_system_samples(root: Path, created_files: list[dict[str, object]]) -> None:
    hidden_file = root / "Engineering" / "Data" / "Current" / ".hidden_frontend_scan_test.txt"
    write_text(
        hidden_file,
        """
CONFIDENTIAL hidden engineering sample.
api_key=crg_hidden_SYNTHETIC_TOKEN
Owner: engineering-owner@caspian-retail.example
Purpose: validates hidden-file filters and Windows attribute collection.
""",
    )
    set_windows_attributes(hidden_file, "+H")
    created_files.append({
        "path": str(hidden_file.relative_to(root)),
        "department": "Engineering",
        "share": "Data",
        "extension": ".txt",
        "hidden": True,
    })

    hidden_env = root / "IT" / "Cloud" / "Secure" / ".shadow_admin_tokens.env"
    write_text(
        hidden_env,
        """
AWS_ACCESS_KEY_ID=AKIA0000HIDDENSYNTH
AWS_SECRET_ACCESS_KEY=synthetic_hidden_secret_value
password=HiddenWinter2026!
""",
    )
    set_windows_attributes(hidden_env, "+H")
    created_files.append({
        "path": str(hidden_env.relative_to(root)),
        "department": "IT",
        "share": "Cloud",
        "extension": ".env",
        "hidden": True,
    })

    system_file = root / "IT" / "ServiceDesk" / "SystemSignals" / "current_system_inventory.sys"
    system_file.parent.mkdir(parents=True, exist_ok=True)
    system_file.write_bytes(b"SYSTEM_SYNTHETIC_DSPM_SAMPLE\x00owner=IT\\service-desk")
    set_windows_attributes(system_file, "+S")
    created_files.append({
        "path": str(system_file.relative_to(root)),
        "department": "IT",
        "share": "ServiceDesk",
        "extension": ".sys",
        "system": True,
    })

    archive_root = root / "Finance" / "Audit" / "Secure"
    protected_zip = archive_root / "protected_finance_archive.zip"
    encrypted = write_password_protected_zip(
        protected_zip,
        "finance_private_export.csv",
        "name,email,card\nSynthetic Customer,customer@example.invalid,4111 1111 1111 1111",
    )
    created_files.append({
        "path": str(protected_zip.relative_to(root)),
        "department": "Finance",
        "share": "Audit",
        "extension": ".zip",
        "protected": encrypted,
    })

    nested_zip = archive_root / "nested_sensitive_exports.zip"
    nested_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(nested_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("exports/customer_fin_values.csv", "name,fin\nSynthetic Person,A123456\n")
        archive.writestr("secrets/release_token.env", "token=synthetic_nested_release_token\n")
    created_files.append({
        "path": str(nested_zip.relative_to(root)),
        "department": "Finance",
        "share": "Audit",
        "extension": ".zip",
        "archive_entries": True,
    })


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic enterprise file-server dataset for DSPM testing.")
    parser.add_argument("--output", default="enterprise_test_data", help="Output directory to recreate.")
    parser.add_argument("--files-per-share", type=int, default=8, help="Number of generated files per department share.")
    args = parser.parse_args()
    generate(Path(args.output), args.files_per_share)
    print(f"Generated synthetic enterprise dataset at {Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
