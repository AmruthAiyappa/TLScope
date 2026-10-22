"""
Tests for PDF Report Generation Service.
"""

from services.report_generator import generate_pdf_report


def test_pdf_generation_complete_data():
    scan_data = {
        "hostname": "example.com",
        "port": 443,
        "ip_address": "93.184.216.34",
        "scan_timestamp": "2026-10-22 12:00:00 UTC",
        "overall_outcome": "SECURE",
        "educational_score": 95,
        "verification_passed": True,
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "passed_count": 8,
        "warning_count": 1,
        "failure_count": 0,
        "certificate_details": {
            "parsed_successfully": True,
            "subject_common_name": "example.com",
            "issuer_common_name": "DigiCert Global Root CA",
            "subject_alternative_names": ["example.com", "www.example.com"],
            "hostname_match_details": "Exact match with SAN",
            "valid_from_iso": "2026-01-01 00:00:00 UTC",
            "valid_to_iso": "2027-01-01 00:00:00 UTC",
            "days_remaining": 70,
            "public_key_details": "RSA 2048-bit",
            "signature_algorithm": "sha256WithRSAEncryption",
            "serial_number_hex": "01:23:45:67:89:AB:CD:EF",
            "fingerprint_sha256": "AA:BB:CC:DD:EE:FF",
            "key_usages": ["Digital Signature", "Key Encipherment"]
        },
        "findings": [
            {
                "finding_id": "TRUST-01",
                "title": "Trust Chain Verification",
                "severity": "Informational",
                "status": "Pass",
                "evidence": "CA signature verified",
                "implication": "Authentic identity",
                "recommendation": "Maintain renewals"
            }
        ]
    }

    pdf_buffer = generate_pdf_report(scan_data)
    pdf_bytes = pdf_buffer.getvalue()
    
    assert len(pdf_bytes) > 1000
    # PDF magic header
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_generation_missing_cert():
    scan_data = {
        "hostname": "offline.example.com",
        "port": 443,
        "ip_address": "93.184.216.34",
        "scan_timestamp": "2026-10-22 12:00:00 UTC",
        "overall_outcome": "FAILED",
        "educational_score": None,
        "verification_passed": False,
        "certificate_details": {
            "parsed_successfully": False,
            "error": "Connection timed out"
        },
        "findings": []
    }

    pdf_buffer = generate_pdf_report(scan_data)
    pdf_bytes = pdf_buffer.getvalue()
    assert pdf_bytes.startswith(b"%PDF-")
