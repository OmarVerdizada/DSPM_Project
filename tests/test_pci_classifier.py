import unittest
import hashlib

from classification.compliance.pci_classifier import classify_pci_content
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class PCIClassifierTests(unittest.TestCase):
    def test_detects_readable_pan_with_payment_context(self):
        findings = classify_pci_content(
            "card_number: 4111 1111 1111 1111\npayment authorization export",
            {"name": "cardholder-data.csv", "path": r"C:\PCI\cardholder-data.csv", "extension": ".csv"},
        )
        pan = next(item for item in findings if item["type"] == "pci_chd_pan")

        self.assertEqual(pan["risk"], "CRITICAL")
        self.assertEqual(pan["protection_state"], "READABLE_FULL")
        self.assertIn("411111******1111", pan["samples"])
        self.assertNotIn("4111 1111 1111 1111", str(pan))

    def test_structured_csv_correlates_pan_and_cvv_only_within_same_row(self):
        same_row = classify_pci_content(
            "card_number,cvv,expiration_date\n4111111111111111,123,12/29\n",
            {"name": "cards.csv", "extension": ".csv"},
        )
        composite = next(item for item in same_row if item["type"] == "pci_composite_sad")

        self.assertEqual(composite["logical_boundary"], "structured_row")
        cvv = next(item for item in same_row if item["type"] == "pci_sad_cvv")
        self.assertEqual(cvv["structured_location"]["row_number"], 2)

        distant_row = classify_pci_content(
            "card_number,cvv\n4111111111111111,\n,123\n",
            {"name": "cards.csv", "extension": ".csv"},
        )

        self.assertFalse(any(item["type"] == "pci_composite_sad" for item in distant_row))

    def test_structured_xlsx_markers_use_sheet_row_cell_location(self):
        findings = classify_pci_content(
            "[xlsx sheet=Payments row=1] A1=card_number | B1=cvv\n"
            "[xlsx sheet=Payments row=15] A15=4111111111111111 | B15=123\n"
            "[xlsx sheet=Payments row=890] A890= | B890=999\n",
            {"name": "cards.xlsx", "extension": ".xlsx"},
        )
        cvv = next(item for item in findings if item["type"] == "pci_sad_cvv")

        self.assertEqual(cvv["logical_boundary"], "structured_row")
        self.assertEqual(cvv["structured_location"]["sheet_name"], "Payments")
        self.assertEqual(cvv["structured_location"]["row_number"], 15)
        self.assertEqual(cvv["structured_location"]["cell_address"], "B15")

    def test_detects_bare_luhn_valid_pan_for_review(self):
        findings = classify_pci_content("4111111111111111", {"name": "unknown.txt", "extension": ".txt"})
        pan = next(item for item in findings if item["type"] == "pci_chd_pan")

        self.assertEqual(pan["protection_state"], "READABLE_FULL")
        self.assertGreaterEqual(pan["confidence"], 55)

    def test_discovery_output_includes_explicit_finding_taxonomy(self):
        record = {
            "name": "payment.txt",
            "path": r"C:\PCI\payment.txt",
            "extension": ".txt",
            "content": "card_number: 4111111111111111",
            "acl": {"aces": [{"principal": "Everyone", "rights": ["Read"]}]},
        }

        analyzed = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(record)
        pan = next(item for item in analyzed["findings"] if item["type"] == "pci_chd_pan")

        self.assertEqual(pan["classification_domain"], "regulated_payment_card")
        self.assertIn("pci_dss", pan["frameworks"])
        self.assertEqual(pan["data_category"], "pci_cardholder_data")
        self.assertTrue(pan["finding_category"])
        self.assertTrue(pan["finding_id"].startswith("finding_"))
        self.assertEqual(pan["entity_type"], "PAN")
        self.assertIn("PCI DSS", pan["framework_mappings"])
        self.assertEqual(pan["impact_severity"], "CRITICAL")
        self.assertGreaterEqual(pan["risk_score"], 90)
        self.assertTrue(pan["asset_id"].startswith("asset_"))
        self.assertTrue(pan["location_id"].startswith("location_"))
        self.assertTrue(pan["logical_boundary_id"].startswith("boundary_"))
        self.assertEqual(pan["occurrence_count"], 1)
        self.assertEqual(pan["unique_value_count"], 1)
        self.assertEqual(pan["protection_state"], "READABLE_FULL")
        self.assertIn("first_seen", pan)
        self.assertIn("last_seen", pan)
        # The lifecycle starts OPEN; the detector's own "unreviewed" stays its review_status.
        self.assertEqual(pan["status"], "OPEN")
        self.assertEqual(pan["review_status"], "unreviewed")
        self.assertTrue(pan["evidence_ids"])
        occurrence = pan["occurrences"][0]
        self.assertTrue(occurrence["occurrence_id"].startswith("occurrence_"))
        # B1.4: an occurrence no longer repeats its parent's ids - the finding above
        # it carries them, and every row that said them again was one row of waste.
        self.assertNotIn("finding_id", occurrence)
        self.assertNotIn("file_id", occurrence)
        self.assertEqual(occurrence["redacted_sample"], "411111******1111")
        self.assertEqual(pan["evidence_ids"], [occurrence["occurrence_id"]],
                         "the finding is still the way back from an occurrence to its file")

    def test_full_pan_is_not_downgraded_by_protection_labels(self):
        for label in ("encrypted pan", "tokenized pan", "pan last four"):
            with self.subTest(label=label):
                findings = classify_pci_content(
                    f"{label}: 4111111111111111",
                    {"name": "cardholder-data.txt", "extension": ".txt"},
                )
                pan = next(item for item in findings if item["type"] == "pci_chd_pan")

                self.assertEqual(pan["protection_state"], "READABLE_FULL")
                self.assertEqual(pan["claimed_protection_state"], "ENCRYPTED" if "encrypted" in label else "TOKENIZED_NONREVERSIBLE_OR_OUT_OF_SCOPE_CANDIDATE" if "tokenized" in label else "TRUNCATED_AT_REST")
                self.assertEqual(pan["verified_protection_state"], "READABLE_FULL")
                removed_field = "protection_" + "".join(["a", "s", "s", "u", "r", "a", "n", "c", "e"])
                self.assertNotIn(removed_field, pan)
                self.assertEqual(pan["impact_severity"], "CRITICAL")
                self.assertEqual(pan["risk"], "CRITICAL")

    def test_pan_fingerprint_uses_tenant_hmac_metadata(self):
        findings = classify_pci_content(
            "card number: 4111111111111111",
            {"name": "payment.txt", "extension": ".txt", "tenant_id": "tenant-a"},
        )
        pan = next(item for item in findings if item["type"] == "pci_chd_pan")
        plain_sha = hashlib.sha256("pci-pan-v1:4111111111111111".encode("utf-8")).hexdigest()

        self.assertNotEqual(pan["secure_fingerprints"][0], plain_sha)
        self.assertEqual(pan["fingerprint_algorithm"], "HMAC-SHA-256")
        self.assertEqual(pan["tenant_id"], "tenant-a")
        self.assertEqual(pan["fingerprint_key_version"], "tenant-evidence-v1")
        self.assertEqual(pan["requirement_mappings"][0]["framework_version"], "4.0.1")
        self.assertIn("effective_from", pan["requirement_mappings"][0])
        self.assertIn("source_reference", pan["requirement_mappings"][0])
        self.assertEqual(pan["card_brand"], "visa")
        self.assertTrue(pan["test_card"])

    def test_rejects_generic_invoice_number_context(self):
        findings = classify_pci_content(
            "invoice number: 4111 1111 1111 1111\norder number for sample data",
            {"name": "invoice.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_chd_pan", {item["type"] for item in findings})

    def test_rejects_invalid_luhn_pan_even_with_payment_context(self):
        findings = classify_pci_content(
            "card_number: 4111 1111 1111 1112 payment authorization",
            {"name": "payment.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_chd_pan", {item["type"] for item in findings})

    def test_known_test_cards_are_flagged_but_not_suppressed(self):
        findings = classify_pci_content(
            "card number: 5555555555554444 payment authorization production export",
            {"name": "prod-card-export.csv", "path": r"C:\Prod\prod-card-export.csv", "extension": ".csv"},
        )
        pan = next(item for item in findings if item["type"] == "pci_chd_pan")

        self.assertTrue(pan["test_card"])
        self.assertEqual(pan["card_brand"], "mastercard")
        self.assertTrue(pan["production_test_pan_policy"])

    def test_detects_masked_pan_without_creating_full_pan(self):
        findings = classify_pci_content(
            "masked PAN: **** **** **** 1111 shown on payment receipt",
            {"name": "receipt.txt", "extension": ".txt"},
        )
        finding_types = {item["type"] for item in findings}

        self.assertIn("pci_chd_masked_pan", finding_types)
        self.assertNotIn("pci_chd_pan", finding_types)

    def test_detects_hashed_pan_artifact(self):
        findings = classify_pci_content(
            "pan_hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            {"name": "token-vault-export.json", "extension": ".json"},
        )

        self.assertIn("pci_hashed_pan", {item["type"] for item in findings})

    def test_ambiguous_hex_pan_artifact_gets_one_protection_state(self):
        findings = classify_pci_content(
            "encrypted_pan: 9f86d081884c7d659a2feaa0c55ad015",
            {"name": "token-vault-export.json", "extension": ".json"},
        )
        transformed = [item for item in findings if item["type"] in {"pci_hashed_pan", "pci_encrypted_pan"}]

        self.assertEqual(len(transformed), 1)
        self.assertEqual(transformed[0]["type"], "pci_encrypted_pan")

    def test_detects_cardholder_name_linked_to_readable_pan(self):
        findings = classify_pci_content(
            "name_on_card: OMAR VERDIZADA\ncard_number: 4111 1111 1111 1111\npayment authorization",
            {"name": "cardholder-data.csv", "path": r"C:\PCI\cardholder-data.csv", "extension": ".csv"},
        )
        name = next(item for item in findings if item["type"] == "pci_chd_cardholder_name")

        self.assertEqual(name["risk"], "HIGH")
        self.assertIn("pan", name["correlated_elements"])
        self.assertIn("O***R V***A", name["samples"])
        self.assertNotIn("OMAR VERDIZADA", str(name))

    def test_allows_low_explicit_name_on_card_without_pan(self):
        findings = classify_pci_content(
            "name_on_card: Leyla Mammadova",
            {"name": "payment-form.txt", "extension": ".txt"},
        )
        name = next(item for item in findings if item["type"] == "pci_chd_cardholder_name")

        self.assertEqual(name["risk"], "LOW")
        self.assertEqual(name["correlated_elements"], [])

    def test_rejects_generic_customer_name_without_payment_context(self):
        findings = classify_pci_content(
            "customer_name: Leyla Mammadova\ninvoice number: 1000000000000001",
            {"name": "invoice.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_chd_cardholder_name", {item["type"] for item in findings})

    def test_detects_expiration_date_linked_to_readable_pan(self):
        findings = classify_pci_content(
            "card_number: 4111 1111 1111 1111\nexpiry_date: 12/29\npayment authorization",
            {"name": "cardholder-data.csv", "path": r"C:\PCI\cardholder-data.csv", "extension": ".csv"},
        )
        expiry = next(item for item in findings if item["type"] == "pci_chd_expiration_date")

        self.assertEqual(expiry["risk"], "HIGH")
        self.assertIn("pan", expiry["correlated_elements"])
        self.assertEqual(expiry["samples"], ["12/2029"])

    def test_detects_expiration_month_year_pair(self):
        findings = classify_pci_content(
            "card_exp_month=7\ncard_exp_year=2030\npayment card token reference",
            {"name": "payment-form.txt", "extension": ".txt"},
        )
        expiry = next(item for item in findings if item["type"] == "pci_chd_expiration_date")

        self.assertEqual(expiry["risk"], "LOW")
        self.assertEqual(expiry["samples"], ["07/2030"])

    def test_rejects_non_payment_expiry_context(self):
        findings = classify_pci_content(
            "certificate expiry: 12/29\nlicense expiry: 11/2030",
            {"name": "certificates.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_chd_expiration_date", {item["type"] for item in findings})

    def test_detects_service_code_linked_to_readable_pan(self):
        findings = classify_pci_content(
            "card_number: 4111 1111 1111 1111\nservice_code: 201\npayment authorization",
            {"name": "cardholder-data.csv", "path": r"C:\PCI\cardholder-data.csv", "extension": ".csv"},
        )
        service_code = next(item for item in findings if item["type"] == "pci_chd_service_code")

        self.assertEqual(service_code["risk"], "HIGH")
        self.assertIn("pan", service_code["correlated_elements"])
        self.assertEqual(service_code["samples"], ["201"])

    def test_allows_low_explicit_service_code_without_pan(self):
        findings = classify_pci_content(
            "track_service_code: 101\npayment card authorization profile",
            {"name": "payment-config.txt", "extension": ".txt"},
        )
        service_code = next(item for item in findings if item["type"] == "pci_chd_service_code")

        self.assertEqual(service_code["risk"], "LOW")
        self.assertEqual(service_code["correlated_elements"], [])

    def test_rejects_generic_status_and_response_codes(self):
        findings = classify_pci_content(
            "http_status_code: 404\nresponse_code: 200\nservice_id: 123",
            {"name": "api-status.log", "extension": ".log"},
        )

        self.assertNotIn("pci_chd_service_code", {item["type"] for item in findings})

    def test_rejects_four_digit_service_code(self):
        findings = classify_pci_content(
            "service_code: 1234\npayment authorization",
            {"name": "payment-config.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_chd_service_code", {item["type"] for item in findings})

    def test_detects_track_1_as_critical_sad(self):
        findings = classify_pci_content(
            "track1_data: %B4111111111111111^VERDIZADA/OMAR^29122010000000000000?",
            {"name": "swipe.log", "path": r"C:\PCI\swipe.log", "extension": ".log"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["risk"], "CRITICAL")
        self.assertEqual(track["pci_category"], "SAD")
        self.assertIn("discretionary_data", track["correlated_elements"])
        self.assertIn("PAN=411111******1111", track["samples"][0])
        self.assertNotIn("%B4111111111111111", str(track))

    def test_detects_track_2_as_critical_sad(self):
        findings = classify_pci_content(
            "track2_data: ;4111111111111111=29122010000000000000?",
            {"name": "processor.log", "extension": ".log"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["risk"], "CRITICAL")
        self.assertEqual(track["track_parser"]["track_type"], "track_2")

    def test_detects_emv_track_2_equivalent(self):
        findings = classify_pci_content(
            "emv_tag_57: 4111111111111111D29122010000000000000F",
            {"name": "emv.json", "extension": ".json"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["track_parser"]["track_type"], "emv_track_2_equivalent")
        self.assertEqual(track["risk"], "CRITICAL")

    def test_detects_ber_tlv_emv_tag_57(self):
        findings = classify_pci_content(
            "emv_payload: 57134111111111111111D29122010000000000000F",
            {"name": "emv-tlv.json", "extension": ".json"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["track_parser"]["track_type"], "emv_track_2_equivalent")
        self.assertEqual(track["track_parser"]["emv_parser"], "ber_tlv_tag_57")
        self.assertEqual(track["track_parser"]["tag"], "57")
        self.assertTrue(track["track_parser"]["padding_nibble_valid"])

    def test_detects_percent_encoded_track_data(self):
        findings = classify_pci_content(
            "raw_swipe_data=%25B4111111111111111%5EVERDIZADA/OMAR%5E29122010000000000000%3F",
            {"name": "reader-payload.log", "extension": ".log"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["track_parser"]["encoding"], "percent_encoded")

    def test_detects_base64_encoded_track_data(self):
        findings = classify_pci_content(
            "track_payload: JUI0MTExMTExMTExMTExMTExXlZFUkRJWkFEQS9PTUFSXjI5MTIyMDEwMDAwMDAwMDAwMDAwPw==",
            {"name": "reader-payload.log", "extension": ".log"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["track_parser"]["encoding"], "base64")

    def test_detects_hex_encoded_track_data(self):
        findings = classify_pci_content(
            "track_payload: 3B343131313131313131313131313131313D32393132323031303030303030303030303030303F",
            {"name": "reader-payload.log", "extension": ".log"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["track_parser"]["encoding"], "hex")

    def test_malformed_emv_tlv_does_not_fail_scan(self):
        findings = classify_pci_content(
            "emv payload: 5780",
            {"name": "bad-emv.log", "extension": ".log"},
        )

        self.assertNotIn("pci_sad_track_data", {item["type"] for item in findings})

    def test_detects_encrypted_track_artifact_as_sad(self):
        findings = classify_pci_content(
            "encrypted_track: QWxhZGRpbjpvcGVuIHNlc2FtZSB0cmFjayBkYXRhIGNpcGhlcnRleHQ=",
            {"name": "encrypted-track.txt", "extension": ".txt"},
        )
        track = next(item for item in findings if item["type"] == "pci_sad_track_data")

        self.assertEqual(track["protection_state"], "ENCRYPTED")
        self.assertEqual(track["risk"], "CRITICAL")

    def test_rejects_non_payment_track_context(self):
        findings = classify_pci_content(
            "music track: ;4111111111111111=29122010000000000000?",
            {"name": "playlist.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_sad_track_data", {item["type"] for item in findings})

    def test_detects_cvv_linked_to_readable_pan_as_critical_sad(self):
        findings = classify_pci_content(
            "card_number: 4111 1111 1111 1111\nexpiry_date: 12/29\ncvv: 123",
            {"name": "payment-request.log", "path": r"C:\PCI\payment-request.log", "extension": ".log"},
        )
        cvv = next(item for item in findings if item["type"] == "pci_sad_cvv")
        composite = next(item for item in findings if item["type"] == "pci_composite_sad")
        pan = next(item for item in findings if item["type"] == "pci_chd_pan")

        self.assertEqual(cvv["risk"], "CRITICAL")
        self.assertEqual(cvv["pci_category"], "SAD")
        self.assertEqual(cvv["samples"], ["CVV_LEN=3"])
        self.assertIn("pan", cvv["correlated_elements"])
        self.assertNotIn("123", str(cvv["samples"]))
        self.assertTrue(cvv["exception_required"])
        self.assertEqual(cvv["storage_state"], "log_or_diagnostic")
        self.assertEqual(cvv["logical_boundary"], "log_event_or_text_window")
        self.assertEqual(composite["pci_category"], "SAD")
        self.assertIn("pci_sad_cvv", composite["child_finding_types"])
        self.assertIn("pci_composite_sad", pan["suppressed_by"])

    def test_detects_explicit_cvv_without_pan_as_critical_sad(self):
        findings = classify_pci_content(
            "card_cvc: 012\npayment form submission",
            {"name": "payment-form.log", "extension": ".log"},
        )
        cvv = next(item for item in findings if item["type"] == "pci_sad_cvv")

        self.assertEqual(cvv["risk"], "CRITICAL")
        self.assertEqual(cvv["samples"], ["CVV_LEN=3"])

    def test_rejects_masked_null_and_placeholder_cvv_values(self):
        findings = classify_pci_content(
            "cvv: ***\ncvc: null\ncid: placeholder",
            {"name": "payment-form.log", "extension": ".log"},
        )

        self.assertNotIn("pci_sad_cvv", {item["type"] for item in findings})

    def test_rejects_two_digit_cvv(self):
        findings = classify_pci_content(
            "cvv: 12\npayment form submission",
            {"name": "payment-form.log", "extension": ".log"},
        )

        self.assertNotIn("pci_sad_cvv", {item["type"] for item in findings})

    def test_rejects_five_digit_cvv(self):
        findings = classify_pci_content(
            "cvv: 12345\npayment form submission",
            {"name": "payment-form.log", "extension": ".log"},
        )

        self.assertNotIn("pci_sad_cvv", {item["type"] for item in findings})

    def test_distant_pan_and_cvv_do_not_create_composite_sad(self):
        findings = classify_pci_content(
            "card_number: 4111111111111111\n" + ("x" * 1000) + "\ncvv: 123",
            {"name": "payment-request.log", "extension": ".log"},
        )
        cvv = next(item for item in findings if item["type"] == "pci_sad_cvv")

        self.assertEqual(cvv["correlated_elements"], [])
        self.assertNotIn("pci_composite_sad", {item["type"] for item in findings})

    def test_same_and_adjacent_row_pan_cvv_create_composite_sad(self):
        for content in (
            "card_number: 4111111111111111 cvv: 123",
            "card_number: 4111111111111111\ncvv: 123",
        ):
            with self.subTest(content=content):
                findings = classify_pci_content(content, {"name": "payment-request.log", "extension": ".log"})
                cvv = next(item for item in findings if item["type"] == "pci_sad_cvv")

                self.assertIn("pan", cvv["correlated_elements"])
                self.assertIn("pci_composite_sad", {item["type"] for item in findings})

    def test_rejects_otp_postal_and_status_codes_as_cvv(self):
        findings = classify_pci_content(
            "otp: 123\npostal_code: 1000\nhttp_status: 404\nverification_code: 777",
            {"name": "auth.log", "extension": ".log"},
        )

        self.assertNotIn("pci_sad_cvv", {item["type"] for item in findings})

    def test_detects_payment_pin_linked_to_readable_pan_as_critical_sad(self):
        findings = classify_pci_content(
            "card_number: 4111 1111 1111 1111\natm_pin: 0123\npayment authorization",
            {"name": "atm-request.log", "path": r"C:\PCI\atm-request.log", "extension": ".log"},
        )
        pin = next(item for item in findings if item["type"] == "pci_sad_pin")

        self.assertEqual(pin["risk"], "CRITICAL")
        self.assertEqual(pin["samples"], ["PIN_LEN=4"])
        self.assertIn("pan", pin["correlated_elements"])
        self.assertNotIn("0123", str(pin["samples"]))

    def test_detects_pin_block_as_critical_sad(self):
        findings = classify_pci_content(
            "encrypted_pin_block: 041234FFFFFFFFFF\nzpk: active hsm payment switch",
            {"name": "switch.log", "extension": ".log"},
        )
        pin_block = next(item for item in findings if item["type"] == "pci_sad_pin_block")

        self.assertEqual(pin_block["risk"], "CRITICAL")
        self.assertEqual(pin_block["samples"], ["PIN_BLOCK_LEN=16"])
        self.assertTrue(pin_block["exception_required"])
        self.assertEqual(pin_block["pin_block_format"], "ISO_FORMAT_0")
        self.assertTrue(pin_block["pin_block_length_valid"])
        self.assertTrue(pin_block["key_co_location_risk"])

    def test_sad_exception_requires_lifecycle_review_even_for_issuer_preauth(self):
        findings = classify_pci_content(
            "issuer pre-authorization cvv: 123",
            {"name": "issuer-auth.log", "extension": ".log"},
        )
        cvv = next(item for item in findings if item["type"] == "pci_sad_cvv")

        self.assertTrue(cvv["exception_required"])
        self.assertEqual(cvv["exception_status"], "required")
        self.assertEqual(cvv["sad_lifecycle_status"], "ISSUER_LEGITIMATE_NEED_REVIEW")

    def test_detects_pan_reconstruction_risk_in_logical_artifact(self):
        findings = classify_pci_content(
            "customer_id=42 first_six: 411111 middle_six: 111111 last_four: 1111",
            {"name": "fragments.csv", "extension": ".csv"},
        )
        reconstruction = next(item for item in findings if item["type"] == "pci_pan_reconstruction_risk")

        self.assertEqual(reconstruction["risk"], "CRITICAL")
        self.assertEqual(reconstruction["reconstruction_parts"], ["first", "last", "middle"])
        self.assertEqual(reconstruction["requirement_mappings"][0]["framework_version"], "4.0.1")

    def test_rejects_device_and_meeting_pin_context(self):
        findings = classify_pci_content(
            "windows_pin: 1234\ndevice pin: 4321\nmeeting_pin: 999999",
            {"name": "device.txt", "extension": ".txt"},
        )

        self.assertNotIn("pci_sad_pin", {item["type"] for item in findings})

    def test_creates_enriched_chd_record_for_pan_with_chd_elements(self):
        findings = classify_pci_content(
            "name_on_card: OMAR VERDIZADA\ncard_number: 4111 1111 1111 1111\nexpiry_date: 12/29\nservice_code: 201\npayment authorization",
            {"name": "prod-cardholder-export.csv", "path": r"C:\Prod\exports\prod-cardholder-export.csv", "extension": ".csv"},
        )
        enriched = next(item for item in findings if item["type"] == "pci_enriched_chd_record")
        pan = next(item for item in findings if item["type"] == "pci_chd_pan")

        self.assertEqual(enriched["risk"], "CRITICAL")
        self.assertEqual(enriched["pci_category"], "CHD")
        self.assertEqual(enriched["environment"], "production")
        self.assertEqual(enriched["storage_state"], "export_or_report")
        self.assertIn("pci_chd_expiration_date", enriched["child_finding_types"])
        self.assertIn("pci_enriched_chd_record", pan["suppressed_by"])

    def test_custom_pci_keywords_create_context_observation_only(self):
        findings = classify_pci_content(
            "processor zone alpha-payment-switch handles nightly payment routing.",
            {"name": "processor-notes.txt", "extension": ".txt"},
            [
                {
                    "framework": "pci_dss",
                    "type": "pci_processor_context",
                    "category": "pci_scope_context",
                    "label": "Processor context",
                    "risk": "MEDIUM",
                    "terms": ["alpha-payment-switch"],
                }
            ],
        )
        custom = next(item for item in findings if item["type"] == "pci_processor_context")

        self.assertEqual(custom["pci_category"], "CONTEXT")
        self.assertEqual(custom["category"], "pci_scope_context")
        self.assertFalse(custom["scope_candidate"])
        self.assertNotIn("pci_chd_pan", {item["type"] for item in findings})

    def test_negative_corpus_does_not_promote_operational_numbers_to_pci(self):
        findings = classify_pci_content(
            "\n".join(
                [
                    "invoice number: 4111 1111 1111 1111",
                    "order number: 5555555555554444",
                    "otp: 123",
                    "postal_code: 1000",
                    "http_status_code: 404",
                    "windows_pin: 1234",
                    "music track: ;4111111111111111=29122010000000000000?",
                ]
            ),
            {"name": "ops-log.txt", "extension": ".txt"},
        )

        self.assertFalse({item["type"] for item in findings} & {"pci_chd_pan", "pci_sad_cvv", "pci_sad_pin", "pci_sad_track_data"})

    def test_discovery_engine_adds_pci_only_when_selected_and_redacts_preview(self):
        record = {
            "source": "local",
            "path": "cardholder-data.txt",
            "name": "cardholder-data.txt",
            "size": 80,
            "extension": ".txt",
            "content": "card number: 4111 1111 1111 1111 payment authorization",
            "acl": {},
        }

        disabled = DSPMDiscoveryEngine(ScanConfig())._analyze_record(dict(record))
        self.assertNotIn("pci_chd_pan", {finding["type"] for finding in disabled["findings"]})

        enabled = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(dict(record))
        enabled_types = {finding["type"] for finding in enabled["findings"]}
        self.assertIn("pci_chd_pan", enabled_types)
        # B7: one card is one finding. The generic rule found it too, and says so,
        # rather than standing beside the PCI one as a second card.
        pan = next(finding for finding in enabled["findings"] if finding["type"] == "pci_chd_pan")
        self.assertIn("credit_card", pan["detected_by"])
        self.assertNotIn("credit_card", enabled_types)
        self.assertIn("411111******1111", "\n".join(enabled["preview"]["lines"]))
        self.assertNotIn("4111 1111 1111 1111", "\n".join(enabled["preview"]["lines"]))

    def test_discovery_engine_redacts_raw_track_preview(self):
        record = {
            "source": "local",
            "path": "swipe.log",
            "name": "swipe.log",
            "size": 120,
            "extension": ".log",
            "content": "track2_data: ;4111111111111111=29122010000000000000?",
            "acl": {},
        }

        enabled = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(dict(record))
        preview = "\n".join(enabled["preview"]["lines"])

        self.assertIn("track_2 PAN=411111******1111", preview)
        self.assertNotIn(";4111111111111111=29122010000000000000?", preview)

    def test_discovery_engine_redacts_cvv_preview(self):
        record = {
            "source": "local",
            "path": "payment-request.log",
            "name": "payment-request.log",
            "size": 100,
            "extension": ".log",
            "content": "card_number: 4111 1111 1111 1111\ncvv: 123",
            "acl": {},
        }

        enabled = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(dict(record))
        preview = "\n".join(enabled["preview"]["lines"])

        self.assertIn("cvv: ***", preview)
        self.assertNotIn("cvv: 123", preview)

    def test_discovery_engine_redacts_pin_preview(self):
        record = {
            "source": "local",
            "path": "atm-request.log",
            "name": "atm-request.log",
            "size": 100,
            "extension": ".log",
            "content": "card_number: 4111 1111 1111 1111\natm_pin: 0123",
            "acl": {},
        }

        enabled = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(dict(record))
        preview = "\n".join(enabled["preview"]["lines"])

        self.assertIn("atm_pin: ***", preview)
        self.assertNotIn("atm_pin: 0123", preview)

    def test_raw_sad_leak_finding_never_contains_raw_cvv_pin_or_track(self):
        findings = classify_pci_content(
            "card_number: 4111111111111111\ncvv: 123\natm_pin: 0123\ntrack2_data: ;4111111111111111=29122010000000000000?",
            {"name": "payment-request.log", "extension": ".log"},
        )
        serialized = str(findings)

        self.assertIn("pci_composite_sad", {item["type"] for item in findings})
        self.assertNotIn("cvv: 123", serialized)
        self.assertNotIn("atm_pin: 0123", serialized)
        self.assertNotIn(";4111111111111111=29122010000000000000?", serialized)

    def test_discovery_engine_attaches_scan_completeness_to_findings(self):
        record = {
            "source": "local",
            "path": "cardholder-data.txt",
            "name": "cardholder-data.txt",
            "size": 300000,
            "extension": ".txt",
            "content": "card_number: 4111 1111 1111 1111",
            "acl": {},
            "scan_completeness": "PARTIAL",
            "bytes_scanned": 262144,
            "total_bytes": 300000,
            "truncated": True,
        }

        enabled = DSPMDiscoveryEngine(ScanConfig(compliance_enabled=True, compliance_frameworks=["pci_dss"]))._analyze_record(dict(record))
        pan = next(item for item in enabled["findings"] if item["type"] == "pci_chd_pan")

        self.assertEqual(pan["scan_completeness"], "PARTIAL")
        self.assertEqual(pan["bytes_scanned"], 262144)
        self.assertTrue(pan["truncated"])


if __name__ == "__main__":
    unittest.main()
