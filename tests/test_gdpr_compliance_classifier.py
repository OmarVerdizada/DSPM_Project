import unittest

from classification.compliance import keywords, raw_gdpr_keywords
from classification.compliance.gdpr_classifier import classify_gdpr_content
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class GDPRComplianceClassifierTests(unittest.TestCase):
    def test_first_batch_raw_keyword_dump_is_merged(self):
        self.assertGreaterEqual(len(keywords.NAME_KEYWORDS), 280)
        self.assertGreaterEqual(len(keywords.GOVERNMENT_ID_KEYWORDS), 590)
        self.assertGreaterEqual(len(keywords.SIGNATURE_KEYWORDS), 620)
        self.assertIn("mother maiden name", keywords.NAME_KEYWORDS)
        self.assertIn("passport_place_of_issue", keywords.GOVERNMENT_ID_KEYWORDS)
        self.assertIn("unsigned document", keywords.SIGNATURE_KEYWORDS)

    def test_second_batch_raw_keyword_dump_is_merged(self):
        self.assertGreaterEqual(len(keywords.PHOTO_FACE_KEYWORDS), 620)
        self.assertGreaterEqual(len(keywords.VEHICLE_KEYWORDS), 430)
        self.assertGreaterEqual(len(keywords.ACCOUNT_RECOVERY_KEYWORDS), 470)
        self.assertGreaterEqual(len(keywords.EMERGENCY_CONTACT_KEYWORDS), 530)
        self.assertIn("face_embedding", keywords.PHOTO_FACE_KEYWORDS)
        self.assertIn("vehicle_identification_number", keywords.VEHICLE_KEYWORDS)
        self.assertIn("security_answer", keywords.ACCOUNT_RECOVERY_KEYWORDS)
        self.assertIn("next_of_kin_phone", keywords.EMERGENCY_CONTACT_KEYWORDS)

    def test_online_device_raw_keyword_dump_is_merged(self):
        self.assertGreaterEqual(len(keywords.IP_IDENTIFIER_KEYWORDS), 500)
        self.assertGreaterEqual(len(keywords.COOKIE_DEVICE_ID_KEYWORDS), 550)
        self.assertGreaterEqual(len(keywords.DEVICE_HARDWARE_KEYWORDS), 410)
        self.assertIn("x-forwarded-for", keywords.IP_IDENTIFIER_KEYWORDS)
        self.assertIn("gclid", keywords.COOKIE_DEVICE_ID_KEYWORDS)
        self.assertIn("imei number", keywords.DEVICE_HARDWARE_KEYWORDS)

    def test_location_browsing_username_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_GEOLOCATION_KEYWORDS), 604)
        self.assertEqual(len(raw_gdpr_keywords.RAW_BROWSING_HISTORY_KEYWORDS), 739)
        self.assertEqual(len(raw_gdpr_keywords.RAW_ACCOUNT_USERNAME_KEYWORDS), 689)
        self.assertGreaterEqual(len(keywords.GEOLOCATION_KEYWORDS), 540)
        self.assertGreaterEqual(len(keywords.BROWSING_HISTORY_KEYWORDS), 600)
        self.assertGreaterEqual(len(keywords.ACCOUNT_USERNAME_KEYWORDS), 520)
        self.assertIn("gps coordinates", keywords.GEOLOCATION_KEYWORDS)
        self.assertIn("clickstream", keywords.BROWSING_HISTORY_KEYWORDS)
        self.assertIn("github username", keywords.ACCOUNT_USERNAME_KEYWORDS)

    def test_special_category_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_HEALTH_MEDICAL_KEYWORDS), 716)
        self.assertEqual(len(raw_gdpr_keywords.RAW_MENTAL_HEALTH_KEYWORDS), 522)
        self.assertEqual(len(raw_gdpr_keywords.RAW_DISABILITY_STATUS_KEYWORDS), 513)
        self.assertEqual(len(raw_gdpr_keywords.RAW_BIOMETRIC_SPECIAL_KEYWORDS), 535)
        self.assertGreaterEqual(len(keywords.HEALTH_MEDICAL_KEYWORDS), 590)
        self.assertGreaterEqual(len(keywords.MENTAL_HEALTH_KEYWORDS), 430)
        self.assertGreaterEqual(len(keywords.DISABILITY_STATUS_KEYWORDS), 430)
        self.assertGreaterEqual(len(keywords.BIOMETRIC_SPECIAL_KEYWORDS), 450)
        self.assertIn("medical record", keywords.HEALTH_MEDICAL_KEYWORDS)
        self.assertIn("substance use", keywords.MENTAL_HEALTH_KEYWORDS)
        self.assertIn("disability status", keywords.DISABILITY_STATUS_KEYWORDS)
        self.assertIn("fingerprint scan", keywords.BIOMETRIC_SPECIAL_KEYWORDS)

    def test_genetic_race_religion_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_GENETIC_DNA_KEYWORDS), 597)
        self.assertEqual(len(raw_gdpr_keywords.RAW_RACE_ETHNICITY_KEYWORDS), 438)
        self.assertEqual(len(raw_gdpr_keywords.RAW_RELIGIOUS_BELIEF_KEYWORDS), 371)
        self.assertGreaterEqual(len(keywords.GENETIC_DNA_KEYWORDS), 520)
        self.assertGreaterEqual(len(keywords.RACE_ETHNICITY_KEYWORDS), 380)
        self.assertGreaterEqual(len(keywords.RELIGIOUS_BELIEF_KEYWORDS), 320)
        self.assertIn("dna sequence", keywords.GENETIC_DNA_KEYWORDS)
        self.assertIn("ethnic origin", keywords.RACE_ETHNICITY_KEYWORDS)
        self.assertIn("religious belief", keywords.RELIGIOUS_BELIEF_KEYWORDS)

    def test_political_sexual_union_immigration_criminal_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_POLITICAL_AFFILIATION_KEYWORDS), 456)
        self.assertEqual(len(raw_gdpr_keywords.RAW_SEXUAL_ORIENTATION_KEYWORDS), 424)
        self.assertEqual(len(raw_gdpr_keywords.RAW_TRADE_UNION_KEYWORDS), 448)
        self.assertEqual(len(raw_gdpr_keywords.RAW_IMMIGRATION_CITIZENSHIP_KEYWORDS), 747)
        self.assertEqual(len(raw_gdpr_keywords.RAW_CRIMINAL_RECORD_KEYWORDS), 569)
        self.assertGreaterEqual(len(keywords.POLITICAL_AFFILIATION_KEYWORDS), 390)
        self.assertGreaterEqual(len(keywords.SEXUAL_ORIENTATION_KEYWORDS), 360)
        self.assertGreaterEqual(len(keywords.TRADE_UNION_KEYWORDS), 380)
        self.assertGreaterEqual(len(keywords.IMMIGRATION_CITIZENSHIP_KEYWORDS), 650)
        self.assertGreaterEqual(len(keywords.CRIMINAL_RECORD_KEYWORDS), 500)
        self.assertIn("political opinion", keywords.POLITICAL_AFFILIATION_KEYWORDS)
        self.assertIn("sexual orientation", keywords.SEXUAL_ORIENTATION_KEYWORDS)
        self.assertIn("union membership", keywords.TRADE_UNION_KEYWORDS)
        self.assertIn("visa status", keywords.IMMIGRATION_CITIZENSHIP_KEYWORDS)
        self.assertIn("criminal record", keywords.CRIMINAL_RECORD_KEYWORDS)

    def test_financial_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_PAYMENT_CARD_KEYWORDS), 690)
        self.assertEqual(len(raw_gdpr_keywords.RAW_BANK_ACCOUNT_KEYWORDS), 598)
        self.assertEqual(len(raw_gdpr_keywords.RAW_TAX_RECORD_KEYWORDS), 593)
        self.assertEqual(len(raw_gdpr_keywords.RAW_SALARY_COMPENSATION_KEYWORDS), 623)
        self.assertEqual(len(raw_gdpr_keywords.RAW_CREDIT_SCORE_REPORT_KEYWORDS), 572)
        self.assertGreaterEqual(len(keywords.PAYMENT_CARD_KEYWORDS), 560)
        self.assertGreaterEqual(len(keywords.BANK_ACCOUNT_KEYWORDS), 510)
        self.assertGreaterEqual(len(keywords.TAX_RECORD_KEYWORDS), 520)
        self.assertGreaterEqual(len(keywords.SALARY_COMPENSATION_KEYWORDS), 540)
        self.assertGreaterEqual(len(keywords.CREDIT_SCORE_REPORT_KEYWORDS), 490)
        self.assertIn("payment card", keywords.PAYMENT_CARD_KEYWORDS)
        self.assertIn("iban", keywords.BANK_ACCOUNT_KEYWORDS)
        self.assertIn("tax return", keywords.TAX_RECORD_KEYWORDS)
        self.assertIn("base salary", keywords.SALARY_COMPENSATION_KEYWORDS)
        self.assertIn("credit score", keywords.CREDIT_SCORE_REPORT_KEYWORDS)

    def test_invoice_prerelease_pricing_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_INVOICE_BILLING_TRANSACTION_KEYWORDS), 662)
        self.assertEqual(len(raw_gdpr_keywords.RAW_PRERELEASE_FINANCIAL_KEYWORDS), 543)
        self.assertEqual(len(raw_gdpr_keywords.RAW_PRICING_MARGIN_FORECAST_KEYWORDS), 794)
        self.assertGreaterEqual(len(keywords.INVOICE_BILLING_TRANSACTION_KEYWORDS), 550)
        self.assertGreaterEqual(len(keywords.PRERELEASE_FINANCIAL_KEYWORDS), 470)
        self.assertGreaterEqual(len(keywords.PRICING_MARGIN_FORECAST_KEYWORDS), 660)
        self.assertIn("brokerage account", keywords.INVOICE_BILLING_TRANSACTION_KEYWORDS)
        self.assertIn("pre-release financial statement", keywords.PRERELEASE_FINANCIAL_KEYWORDS)
        self.assertIn("pricing", keywords.PRICING_MARGIN_FORECAST_KEYWORDS)

    def test_credentials_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_PASSWORD_SECRET_KEYWORDS), 566)
        self.assertEqual(len(raw_gdpr_keywords.RAW_API_TOKEN_SECRET_KEYWORDS), 746)
        self.assertEqual(len(raw_gdpr_keywords.RAW_PRIVATE_KEY_CERT_KEYWORDS), 713)
        self.assertGreaterEqual(len(keywords.PASSWORD_SECRET_KEYWORDS), 520)
        self.assertGreaterEqual(len(keywords.API_TOKEN_SECRET_KEYWORDS), 470)
        self.assertGreaterEqual(len(keywords.PRIVATE_KEY_CERT_KEYWORDS), 510)
        self.assertIn("password", keywords.PASSWORD_SECRET_KEYWORDS)
        self.assertIn("api key", keywords.API_TOKEN_SECRET_KEYWORDS)
        self.assertIn("private key", keywords.PRIVATE_KEY_CERT_KEYWORDS)

    def test_connection_crypto_session_mfa_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_DATABASE_CONNECTION_KEYWORDS), 730)
        self.assertEqual(len(raw_gdpr_keywords.RAW_ENCRYPTION_KEY_MATERIAL_KEYWORDS), 766)
        self.assertEqual(len(raw_gdpr_keywords.RAW_SESSION_TOKEN_JWT_KEYWORDS), 561)
        self.assertEqual(len(raw_gdpr_keywords.RAW_MFA_RECOVERY_KEYWORDS), 550)
        self.assertGreaterEqual(len(keywords.DATABASE_CONNECTION_KEYWORDS), 460)
        self.assertGreaterEqual(len(keywords.ENCRYPTION_KEY_MATERIAL_KEYWORDS), 530)
        self.assertGreaterEqual(len(keywords.SESSION_TOKEN_JWT_KEYWORDS), 380)
        self.assertGreaterEqual(len(keywords.MFA_RECOVERY_KEYWORDS), 400)
        self.assertIn("connection string", keywords.DATABASE_CONNECTION_KEYWORDS)
        self.assertIn("encryption key", keywords.ENCRYPTION_KEY_MATERIAL_KEYWORDS)
        self.assertIn("session token", keywords.SESSION_TOKEN_JWT_KEYWORDS)
        self.assertIn("mfa recovery code", keywords.MFA_RECOVERY_KEYWORDS)

    def test_hr_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_HR_EMPLOYEE_FILE_KEYWORDS), 759)
        self.assertEqual(len(raw_gdpr_keywords.RAW_BENEFITS_INSURANCE_KEYWORDS), 863)
        self.assertEqual(len(raw_gdpr_keywords.RAW_BACKGROUND_DRUG_TEST_KEYWORDS), 865)
        self.assertGreaterEqual(len(keywords.HR_EMPLOYEE_FILE_KEYWORDS), 700)
        self.assertGreaterEqual(len(keywords.BENEFITS_INSURANCE_KEYWORDS), 700)
        self.assertGreaterEqual(len(keywords.BACKGROUND_DRUG_TEST_KEYWORDS), 710)
        self.assertIn("hr file", keywords.HR_EMPLOYEE_FILE_KEYWORDS)
        self.assertIn("employee benefits", keywords.BENEFITS_INSURANCE_KEYWORDS)
        self.assertIn("background check", keywords.BACKGROUND_DRUG_TEST_KEYWORDS)

    def test_hr_operations_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_TIMESHEET_ATTENDANCE_KEYWORDS), 818)
        self.assertEqual(len(raw_gdpr_keywords.RAW_ORG_CHART_DIRECTORY_KEYWORDS), 867)
        self.assertEqual(len(raw_gdpr_keywords.RAW_TERMINATION_LAYOFF_KEYWORDS), 975)
        self.assertGreaterEqual(len(keywords.TIMESHEET_ATTENDANCE_KEYWORDS), 680)
        self.assertGreaterEqual(len(keywords.ORG_CHART_DIRECTORY_KEYWORDS), 660)
        self.assertGreaterEqual(len(keywords.TERMINATION_LAYOFF_KEYWORDS), 770)
        self.assertIn("timesheet", keywords.TIMESHEET_ATTENDANCE_KEYWORDS)
        self.assertIn("org chart", keywords.ORG_CHART_DIRECTORY_KEYWORDS)
        self.assertIn("termination", keywords.TERMINATION_LAYOFF_KEYWORDS)

    def test_corporate_ip_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_SOURCE_CODE_ALGORITHM_KEYWORDS), 943)
        self.assertEqual(len(raw_gdpr_keywords.RAW_TRADE_SECRET_DESIGN_KEYWORDS), 999)
        self.assertEqual(len(raw_gdpr_keywords.RAW_PATENT_PENDING_KEYWORDS), 868)
        self.assertEqual(len(raw_gdpr_keywords.RAW_MA_DUE_DILIGENCE_KEYWORDS), 1009)
        self.assertGreaterEqual(len(keywords.SOURCE_CODE_ALGORITHM_KEYWORDS), 730)
        self.assertGreaterEqual(len(keywords.TRADE_SECRET_DESIGN_KEYWORDS), 830)
        self.assertGreaterEqual(len(keywords.PATENT_PENDING_KEYWORDS), 700)
        self.assertGreaterEqual(len(keywords.MA_DUE_DILIGENCE_KEYWORDS), 750)
        self.assertIn("source code", keywords.SOURCE_CODE_ALGORITHM_KEYWORDS)
        self.assertIn("trade secret", keywords.TRADE_SECRET_DESIGN_KEYWORDS)
        self.assertIn("patent pending", keywords.PATENT_PENDING_KEYWORDS)
        self.assertIn("due diligence", keywords.MA_DUE_DILIGENCE_KEYWORDS)

    def test_governance_legal_vendor_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_BOARD_MATERIALS_KEYWORDS), 1049)
        self.assertEqual(len(raw_gdpr_keywords.RAW_STRATEGY_ROADMAP_PLAN_KEYWORDS), 1168)
        self.assertEqual(len(raw_gdpr_keywords.RAW_CONTRACT_NDA_LEGAL_KEYWORDS), 1065)
        self.assertEqual(len(raw_gdpr_keywords.RAW_LITIGATION_PRIVILEGED_LEGAL_KEYWORDS), 968)
        self.assertEqual(len(raw_gdpr_keywords.RAW_VENDOR_SUPPLIER_TERMS_KEYWORDS), 1230)
        self.assertGreaterEqual(len(keywords.BOARD_MATERIALS_KEYWORDS), 810)
        self.assertGreaterEqual(len(keywords.STRATEGY_ROADMAP_PLAN_KEYWORDS), 950)
        self.assertGreaterEqual(len(keywords.CONTRACT_NDA_LEGAL_KEYWORDS), 830)
        self.assertGreaterEqual(len(keywords.LITIGATION_PRIVILEGED_LEGAL_KEYWORDS), 750)
        self.assertGreaterEqual(len(keywords.VENDOR_SUPPLIER_TERMS_KEYWORDS), 960)
        self.assertIn("board materials", keywords.BOARD_MATERIALS_KEYWORDS)
        self.assertIn("strategy", keywords.STRATEGY_ROADMAP_PLAN_KEYWORDS)
        self.assertIn("contract", keywords.CONTRACT_NDA_LEGAL_KEYWORDS)
        self.assertIn("litigation", keywords.LITIGATION_PRIVILEGED_LEGAL_KEYWORDS)
        self.assertIn("vendor terms", keywords.VENDOR_SUPPLIER_TERMS_KEYWORDS)

    def test_operational_security_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_NETWORK_ARCHITECTURE_KEYWORDS), 1073)
        self.assertEqual(len(raw_gdpr_keywords.RAW_VULNERABILITY_PENTEST_KEYWORDS), 1268)
        self.assertEqual(len(raw_gdpr_keywords.RAW_SECURITY_CONFIG_FIREWALL_KEYWORDS), 1151)
        self.assertGreaterEqual(len(keywords.NETWORK_ARCHITECTURE_KEYWORDS), 850)
        self.assertGreaterEqual(len(keywords.VULNERABILITY_PENTEST_KEYWORDS), 1020)
        self.assertGreaterEqual(len(keywords.SECURITY_CONFIG_FIREWALL_KEYWORDS), 880)
        self.assertIn("network diagram", keywords.NETWORK_ARCHITECTURE_KEYWORDS)
        self.assertIn("vulnerability scan", keywords.VULNERABILITY_PENTEST_KEYWORDS)
        self.assertIn("firewall rule", keywords.SECURITY_CONFIG_FIREWALL_KEYWORDS)

    def test_incident_resilience_physical_raw_keyword_dump_is_merged(self):
        self.assertEqual(len(raw_gdpr_keywords.RAW_INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS), 1329)
        self.assertEqual(len(raw_gdpr_keywords.RAW_DISASTER_RECOVERY_BCP_KEYWORDS), 1198)
        self.assertEqual(len(raw_gdpr_keywords.RAW_PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS), 1278)
        self.assertGreaterEqual(len(keywords.INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS), 1020)
        self.assertGreaterEqual(len(keywords.DISASTER_RECOVERY_BCP_KEYWORDS), 930)
        self.assertGreaterEqual(len(keywords.PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS), 1020)
        self.assertIn("incident report", keywords.INCIDENT_ACCESS_AUDIT_LOG_KEYWORDS)
        self.assertIn("disaster recovery", keywords.DISASTER_RECOVERY_BCP_KEYWORDS)
        self.assertIn("physical security", keywords.PHYSICAL_SECURITY_BADGE_CCTV_KEYWORDS)

    def test_classifies_first_batch_personal_identifiers(self):
        content = "\n".join(
            [
                "Full name: Omar Verdizada",
                "Email address: omar.verdizada@example.com",
                "Phone number: +994 50 123 45 67",
                "Postal address: Z. Aliyeva street 9, Baku, AZ1000",
                "Date of birth: 1993-04-21",
                "FIN code: 5VBK5VR",
                "National ID: AZE 12345678",
                "Passport number: C12345678",
                "signature_value: MEUCIQDxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "signed_form.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_full_name", finding_types)
        self.assertIn("gdpr_email_address", finding_types)
        self.assertIn("gdpr_phone_number", finding_types)
        self.assertIn("gdpr_postal_address", finding_types)
        self.assertIn("gdpr_birth_details", finding_types)
        self.assertIn("gdpr_fin_pin", finding_types)
        self.assertIn("gdpr_national_id", finding_types)
        self.assertIn("gdpr_passport_number", finding_types)
        self.assertIn("gdpr_signature", finding_types)

    def test_classifies_second_batch_personal_identifiers(self):
        content = "\n".join(
            [
                "profile_photo: /uploads/users/123/face_photo.jpg",
                "VIN number: 1HGCM82633A004352",
                "license plate: 10 AA 123",
                "security answer: blue school",
                "emergency contact: Leyla Mammadova, mother, +994 50 123 45 67",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "face_photo.jpg", "extension": ".jpg", "path": "/kyc/face_photo.jpg"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_photo_face_image", finding_types)
        self.assertIn("gdpr_vehicle_identifier", finding_types)
        self.assertIn("gdpr_account_recovery_secret", finding_types)
        self.assertIn("gdpr_emergency_contact", finding_types)

    def test_classifies_online_and_device_identifiers(self):
        content = "\n".join(
            [
                "client_ip: 203.0.113.5",
                "x-forwarded-for: 203.0.113.5, 10.0.0.1",
                "ga client id: GA1.2.123456789.1699999999",
                "gclid=abcdef1234567890",
                "mac address: AA:BB:CC:11:22:33",
                "imei number: 490154203237518",
                "imsi number: 310150123456789",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "online_ids.log", "extension": ".log"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_ip_identifier", finding_types)
        self.assertIn("gdpr_cookie_device_identifier", finding_types)
        self.assertIn("gdpr_device_hardware_identifier", finding_types)

    def test_classifies_location_browsing_and_usernames(self):
        content = "\n".join(
            [
                "gps coordinates: 40.4093, 49.8671",
                "visited url: https://example.com/products?utm_source=ad",
                "search query: dspm compliance rules",
                "github username: omarverdizada",
                "telegram username: @omar_dev",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "activity_export.log", "extension": ".log"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_geolocation", finding_types)
        self.assertIn("gdpr_browsing_history", finding_types)
        self.assertIn("gdpr_account_username", finding_types)

    def test_classifies_special_category_data(self):
        content = "\n".join(
            [
                "medical record: MRN-1234567 diagnosis I10 hypertension prescription aspirin 75mg",
                "mental health assessment: depression with anxiety, therapy session scheduled",
                "disability status: permanent disability certificate, wheelchair accommodation required",
                "fingerprint template: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "special_categories.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_health_medical_record", finding_types)
        self.assertIn("gdpr_mental_health_substance_use", finding_types)
        self.assertIn("gdpr_disability_status", finding_types)
        self.assertIn("gdpr_biometric_special_category", finding_types)

    def test_classifies_genetic_race_and_religious_data(self):
        content = "\n".join(
            [
                "genetic test result: BRCA1 variant c.68_69delAG, rs80357906",
                "dna sequence: ACGTACGTACGTACGTACGT",
                "ethnic origin: Azerbaijani",
                "religious belief: Muslim",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "special_category_export.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_genetic_dna_data", finding_types)
        self.assertIn("gdpr_race_ethnicity", finding_types)
        self.assertIn("gdpr_religious_philosophical_belief", finding_types)

    def test_classifies_political_sexual_union_immigration_and_criminal_data(self):
        content = "\n".join(
            [
                "political affiliation: Green Party campaign volunteer",
                "sexual orientation: bisexual",
                "union membership: labor union member, union card U-123456",
                "visa status: residence permit RP-987654, A-123456789",
                "criminal record: police clearance case CR-2024-55555 no conviction certificate",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "restricted_screening.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_political_affiliation", finding_types)
        self.assertIn("gdpr_sexual_orientation_sex_life", finding_types)
        self.assertIn("gdpr_trade_union_membership", finding_types)
        self.assertIn("gdpr_immigration_citizenship_status", finding_types)
        self.assertIn("gdpr_criminal_record_background_check", finding_types)

    def test_classifies_financial_data(self):
        content = "\n".join(
            [
                "card number: 4111 1111 1111 1111 expiry date: 12/29 cvv: 123",
                "bank account IBAN: GB82WEST12345698765432 swift bic: DEUTDEFF",
                "tax return: 2024 taxable income USD 85,000 taxpayer id TIN-123456789",
                "base salary: AZN 5000 monthly salary bonus AZN 1000",
                "credit score: 720 credit report delinquency none",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "financial_export.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_payment_card_data", finding_types)
        self.assertIn("gdpr_bank_account_data", finding_types)
        self.assertIn("gdpr_tax_record", finding_types)
        self.assertIn("gdpr_salary_compensation", finding_types)
        self.assertIn("gdpr_credit_score_report", finding_types)

    def test_classifies_invoice_prerelease_and_pricing_data(self):
        content = "\n".join(
            [
                "brokerage account: ACCT-998877 portfolio holdings market value USD 125,000",
                "pre-release financial statement: draft income statement revenue USD 5,000,000",
                "confidential pricing: enterprise price list discount 18% floor price USD 75,000",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "commercial_finance_pack.xlsx", "extension": ".xlsx"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_invoice_billing_transaction_log", finding_types)
        self.assertIn("gdpr_prerelease_financial_statement", finding_types)
        self.assertIn("gdpr_pricing_margin_forecast", finding_types)

    def test_classifies_credentials_and_key_material(self):
        content = "\n".join(
            [
                "db password: Sup3rSecret!2026",
                "api key: sk-test_1234567890abcdef1234567890",
                "github token: ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                "private key file: id_rsa",
                "-----BEGIN PRIVATE KEY-----",
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
                "-----END PRIVATE KEY-----",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "secrets.env", "extension": ".env"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_password_secret", finding_types)
        self.assertIn("gdpr_api_token_oauth_secret", finding_types)
        self.assertIn("gdpr_private_key_certificate_secret", finding_types)

    def test_classifies_connection_crypto_session_and_mfa_data(self):
        content = "\n".join(
            [
                "database connection string: postgres://app:Sup3rSecret!@db.internal:5432/customer",
                "encryption key: 0123456789abcdef0123456789abcdef",
                "session token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturevalue123",
                "mfa recovery code: AB12-CD34-EF56-GH78",
                "otpauth://totp/DSPM:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=DSPM",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "runtime_secrets.env", "extension": ".env"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_database_connection_string", finding_types)
        self.assertIn("gdpr_encryption_key_material", finding_types)
        self.assertIn("gdpr_session_token_jwt", finding_types)
        self.assertIn("gdpr_mfa_seed_recovery_code", finding_types)

    def test_classifies_hr_benefits_and_background_data(self):
        content = "\n".join(
            [
                "hr file: employee performance review score exceeds expectations",
                "disciplinary action: written warning for policy violation",
                "benefit enrollment: spouse dependent coverage policy number BEN-123456",
                "background check: police clearance case BG-2025-7788 passed",
                "drug test result: negative toxicology screen",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "employee_hr_file.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_hr_employee_file", finding_types)
        self.assertIn("gdpr_benefits_insurance_enrollment", finding_types)
        self.assertIn("gdpr_background_check_drug_test", finding_types)

    def test_classifies_hr_operations_data(self):
        content = "\n".join(
            [
                "timesheet: employee clock in 09:00 clock out 18:00 overtime hours 2",
                "org chart: Leyla Mammadova reports to Finance Director, department FP&A",
                "termination plan: impacted employee final pay AZN 2500 notice period 30 days",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "hr_operations.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_timesheet_attendance", finding_types)
        self.assertIn("gdpr_org_chart_directory", finding_types)
        self.assertIn("gdpr_termination_layoff_plan", finding_types)

    def test_classifies_corporate_ip_and_deal_data(self):
        content = "\n".join(
            [
                "source code: repository dspm-core algorithm function classifyRisk() schema migration",
                "trade secret: formula TS-42 prototype CAD design document confidential know-how",
                "patent pending: invention disclosure claim draft prior art search provisional filing",
                "due diligence: virtual data room valuation model LOI synergy analysis QoE report",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "corporate_ip_pack.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_source_code_algorithm", finding_types)
        self.assertIn("gdpr_trade_secret_design", finding_types)
        self.assertIn("gdpr_patent_pending_unfiled", finding_types)
        self.assertIn("gdpr_ma_due_diligence", finding_types)

    def test_classifies_governance_legal_and_vendor_data(self):
        content = "\n".join(
            [
                "board minutes: board of directors resolution and audit committee agenda",
                "strategic roadmap: product strategy growth plan market expansion initiative",
                "contract: signed NDA agreement limitation of liability governing law clause",
                "litigation: attorney client privilege legal hold court claim settlement strategy",
                "vendor terms: supplier agreement payment terms SLA rebate approved vendor scorecard",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "governance_legal_pack.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_board_materials_minutes", finding_types)
        self.assertIn("gdpr_strategy_roadmap_plan", finding_types)
        self.assertIn("gdpr_contract_nda_legal", finding_types)
        self.assertIn("gdpr_litigation_privileged_legal", finding_types)
        self.assertIn("gdpr_vendor_supplier_terms", finding_types)

    def test_classifies_operational_security_data(self):
        content = "\n".join(
            [
                "network diagram: production VPC topology subnet CIDR DMZ firewall routing",
                "vulnerability scan: CVE-2026-12345 CVSS 9.8 critical exploit remediation owner",
                "firewall rule: allow tcp 443 ingress security group sg-123 deny admin subnet",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "security_operations_pack.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_network_architecture_diagram", finding_types)
        self.assertIn("gdpr_vulnerability_pentest_report", finding_types)
        self.assertIn("gdpr_security_config_firewall_rule", finding_types)

    def test_classifies_incident_resilience_and_physical_security_data(self):
        content = "\n".join(
            [
                "incident report: unauthorized access security incident IOC affected users root cause analysis",
                "disaster recovery plan: business continuity BCP RTO 4 hours RPO 15 minutes failover runbook",
                "physical security: badge ID BADGE-12345 CCTV camera footage door access ACS floor plan",
            ]
        )
        findings = classify_gdpr_content(content, {"name": "security_resilience_pack.txt", "extension": ".txt"})
        finding_types = {finding["type"] for finding in findings}

        self.assertIn("gdpr_incident_access_audit_log", finding_types)
        self.assertIn("gdpr_disaster_recovery_bcp_plan", finding_types)
        self.assertIn("gdpr_physical_security_badge_cctv", finding_types)

    def test_discovery_engine_only_adds_gdpr_findings_when_enabled(self):
        record = {
            "source": "local",
            "path": "customer.txt",
            "name": "customer.txt",
            "size": 80,
            "extension": ".txt",
            "content": "Full name: Omar Verdizada\nFIN code: 5VBK5VR",
            "acl": {},
        }

        disabled_engine = DSPMDiscoveryEngine(ScanConfig())
        disabled = disabled_engine._analyze_record(dict(record))
        self.assertNotIn("gdpr_full_name", {finding["type"] for finding in disabled["findings"]})

        enabled_engine = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["gdpr"]))
        enabled = enabled_engine._analyze_record(dict(record))
        enabled_types = {finding["type"] for finding in enabled["findings"]}
        self.assertIn("gdpr_full_name", enabled_types)
        self.assertIn("gdpr_fin_pin", enabled_types)


if __name__ == "__main__":
    unittest.main()
