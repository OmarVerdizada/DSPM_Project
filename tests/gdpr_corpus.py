"""A labelled GDPR corpus (D2): what each document really holds, for measuring what the
detectors find and what each confidence tier is worth.

Every value is synthetic. Positives hold personal data the way business files do - a
contact sheet, an HR record, a config file with a password. Negatives are the look-alikes
that fool pattern detectors: version strings and OIDs that look like addresses and IDs,
prose that talks *about* e-mail, health checks and passwords without holding any, and
lorem ipsum. ``expected`` is what a careful reader would say the document contains -
labelled from the text, never from what a detector returned.
"""

from __future__ import annotations

CORPUS: list[dict] = [
    # ---- positives: identifiers ------------------------------------------------------
    {"id": "contact-sheet", "expected": {"gdpr_full_name", "gdpr_email_address", "gdpr_phone_number"},
     "text": "Customer contact sheet\nName: Ana Mammadova\nEmail: ana.mammadova@example.com\n"
             "Phone: +994 50 123 45 67\nPreferred contact: email\n"},
    {"id": "mailing-list", "expected": {"gdpr_email_address", "gdpr_full_name"},
     "text": "Newsletter subscribers export\nfull_name,email\nLeyla Aliyeva,leyla.aliyeva@example.org\n"
             "Rashad Guliyev,rashad.g@example.net\nNigar Hasanova,nigar.h@example.com\n"
             "Elvin Mammadli,elvin.m@example.org\n"},
    {"id": "signature-line", "expected": {"gdpr_email_address", "gdpr_full_name"},
     "text": "Thanks for the update, see you Thursday.\n\nBest regards,\nFarid Ismayilov\nfarid.ismayilov@example.com\n"},
    {"id": "hr-record", "expected": {"gdpr_full_name", "gdpr_birth_details", "gdpr_fin_pin", "gdpr_postal_address"},
     "text": "Employee record - confidential\nEmployee name: Kamala Huseynova\nDate of birth: 14.03.1988\n"
             "FIN: 5ZX8K2P\nHome address: 28 Nizami Street, Baku AZ1000\nDepartment: Finance\n"},
    {"id": "passport-copy", "expected": {"gdpr_full_name", "gdpr_passport_number", "gdpr_birth_details"},
     "text": "Travel desk - passport details for visa application\nTraveller: Murad Aliyev\n"
             "Passport number: C01234567\nDate of birth: 02/11/1979\nNationality: Azerbaijani\n"},
    {"id": "national-ids", "expected": {"gdpr_national_id", "gdpr_full_name"},
     "text": "Identity verification log\nApplicant: Sevda Karimova, national ID number AZE 12345678\n"
             "Applicant: Orkhan Babayev, national ID number AZE 87654321\n"},
    {"id": "access-log", "expected": {"gdpr_ip_identifier", "gdpr_account_username"},
     "text": "Login audit\n2026-09-01 08:14:02 user=ana.m login ok from 85.132.41.17\n"
             "2026-09-01 08:20:40 user=rashad.g login failed from 94.20.66.3\n"},
    {"id": "geo-checkin", "expected": {"gdpr_geolocation", "gdpr_full_name"},
     "text": "Field technician check-ins\nTechnician: Elvin Mammadli, GPS location 40.4093, 49.8671 at 09:12\n"
             "Technician: Nigar Hasanova, GPS location 40.3777, 49.8920 at 10:40\n"},
    # ---- positives: special categories ----------------------------------------------
    {"id": "sick-note", "expected": {"gdpr_full_name", "gdpr_health_medical_record"},
     "text": "Occupational health - sick leave certificate\nPatient: Leyla Aliyeva\n"
             "Diagnosis: type 2 diabetes, prescribed metformin; medical leave 5 days\n"},
    {"id": "union-roster", "expected": {"gdpr_full_name", "gdpr_trade_union_membership"},
     "text": "Trade union membership list - payroll deduction of union dues\n"
             "Member: Rashad Guliyev, union member since 2019\nMember: Kamala Huseynova, union member since 2021\n"},
    {"id": "faith-accommodation", "expected": {"gdpr_full_name", "gdpr_religious_philosophical_belief"},
     "text": "Accommodation request\nEmployee: Murad Aliyev\nReligious belief: practising Muslim; requests prayer "
             "breaks and Ramadan schedule adjustment\n"},
    {"id": "background-check", "expected": {"gdpr_full_name", "gdpr_criminal_record_background_check"},
     "text": "Pre-employment background check\nCandidate: Orkhan Babayev\nCriminal record check: conviction in 2015 "
             "for fraud, sentence served\n"},
    # ---- positives: secrets and finance ---------------------------------------------
    {"id": "app-config", "expected": {"gdpr_password_secret", "gdpr_database_connection_string"},
     "text": "[database]\nhost = db01.corp.example\nuser = app_rw\npassword = Tr0ub4dor&3xYz!\n"
             "url = postgresql://app_rw:Tr0ub4dor%263xYz%21@db01.corp.example:5432/erp\n"},
    {"id": "api-keys", "expected": {"gdpr_api_token_oauth_secret"},
     "text": "# integration settings\nSTRIPE_API_KEY=sk_live_51H8xQ2Lk4Jd9sPq7Vr3Zt6Wm\n"
             "oauth_client_secret = 8f2b9c4e1a7d6f3b0c5e9a2d4f8b1c6e\n"},
    {"id": "salary-review", "expected": {"gdpr_full_name", "gdpr_salary_compensation"},
     "text": "Compensation review 2026 - confidential\nEmployee: Nigar Hasanova, base salary 4,200 AZN per month, "
             "bonus 10%\nEmployee: Elvin Mammadli, base salary 3,650 AZN per month, bonus 8%\n"},
    {"id": "bank-details", "expected": {"gdpr_full_name", "gdpr_bank_account_data"},
     "text": "Payroll bank details\nEmployee: Sevda Karimova\nIBAN: AZ21NABZ00000000137010001944\n"
             "Bank: Example Bank OJSC\n"},
    # ---- negatives: look-alikes -----------------------------------------------------
    {"id": "release-notes", "expected": set(),
     "text": "Release notes 4.2.10\n- Fixed a crash when parsing version 10.4.3.2\n- Upgraded OpenSSL to 3.0.14\n"
             "- Build 20260901.3 uses schema 1.3.6.1.4.1.311\n"},
    {"id": "email-policy", "expected": set(),
     "text": "Email policy\nEmployees must not forward email to personal accounts. Report phishing email to the "
             "security team. Email retention is seven years.\n"},
    {"id": "health-endpoint", "expected": set(),
     "text": "Service runbook\nThe /health endpoint returns 200 when the service is healthy. A failed health "
             "check restarts the pod. Diagnosis: check the logs for timeout errors.\n"},
    {"id": "password-guidance", "expected": set(),
     "text": "Password guidance\nUse a password manager. A strong password has at least 12 characters. "
             "Never share your password. The password field below is required.\n"},
    {"id": "lorem", "expected": set(),
     "text": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut "
             "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation.\n"},
    {"id": "product-catalog", "expected": set(),
     "text": "Product catalogue\nSKU AZE-12345678 steel bracket\nSKU C01234567 cable 2m\nModel 40.4093 rev B\n"
             "Part number 5ZX8K2P-01 gasket\n"},
    {"id": "meeting-notes", "expected": set(),
     "text": "Meeting notes - office move\nAgenda: floor plan, parking, network cabling. Decision: move on "
             "15 October. Next meeting Thursday 10:00 in room 3.\n"},
    {"id": "code-snippet", "expected": set(),
     "text": "def connect(host, port=5432):\n    password = os.environ['DB_PASSWORD']\n"
             "    return psycopg.connect(host=host, port=port, password=password)\n"},
    {"id": "network-diagram-notes", "expected": set(),
     "text": "Lab network\nSubnet 10.0.0.0/24, gateway 10.0.0.1, DNS 10.0.0.53\nTest VM 192.168.56.101\n"},
    {"id": "union-news", "expected": set(),
     "text": "Industry news\nThe European Union published new guidance on data transfers. The trade union "
             "federation welcomed the proposal in a press release.\n"},
]
