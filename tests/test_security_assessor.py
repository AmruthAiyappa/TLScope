"""
Tests for Security Assessor Service.
"""

import pytest
from services.tls_inspector import TLSConnectionResult
from services.certificate_analyzer import CertificateAnalysisResult
from services.security_assessor import assess_security_posture


def test_assessment_connection_failure():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = False
    tls_res.verification_error = "Connection refused"
    cert_res = CertificateAnalysisResult()

    assessment = assess_security_posture(tls_res, cert_res)
    assert assessment.overall_outcome == "FAILED"
    assert assessment.educational_score is None
    assert assessment.failure_count >= 1
    assert any(f.finding_id == "CONN-01" for f in assessment.findings)


def test_assessment_strong_tls_posture():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = True
    tls_res.handshake_completed = True
    tls_res.verification_passed = True
    tls_res.chain_verified_by_ca = True
    tls_res.tls_version = "TLSv1.3"
    tls_res.cipher_name = "TLS_AES_256_GCM_SHA384"
    tls_res.cipher_bits = 256

    cert_res = CertificateAnalysisResult()
    cert_res.parsed_successfully = True
    cert_res.hostname_matched = True
    cert_res.is_valid_now = True
    cert_res.days_remaining = 120
    cert_res.public_key_algorithm = "RSA"
    cert_res.public_key_size = 2048
    cert_res.signature_algorithm = "sha256WithRSAEncryption"
    cert_res.subject_alternative_names = ["example.com"]

    assessment = assess_security_posture(tls_res, cert_res)
    assert assessment.overall_outcome == "SECURE"
    assert assessment.educational_score >= 90
    assert assessment.failure_count == 0
    assert assessment.warning_count == 0


def test_assessment_expired_certificate_failure():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = True
    tls_res.handshake_completed = True
    tls_res.verification_passed = True
    tls_res.chain_verified_by_ca = True
    tls_res.tls_version = "TLSv1.3"
    tls_res.cipher_name = "TLS_AES_256_GCM_SHA384"
    tls_res.cipher_bits = 256

    cert_res = CertificateAnalysisResult()
    cert_res.parsed_successfully = True
    cert_res.hostname_matched = True
    cert_res.is_expired = True
    cert_res.is_valid_now = False
    cert_res.days_remaining = -5
    cert_res.public_key_algorithm = "RSA"
    cert_res.public_key_size = 2048
    cert_res.signature_algorithm = "sha256WithRSAEncryption"
    cert_res.subject_alternative_names = ["example.com"]

    assessment = assess_security_posture(tls_res, cert_res)
    assert assessment.overall_outcome == "INSECURE"
    assert assessment.failure_count >= 1
    time_finding = next(f for f in assessment.findings if f.finding_id == "TIME-01")
    assert time_finding.status == "Fail"
    assert time_finding.severity == "Critical"


def test_assessment_expiring_soon_warning():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = True
    tls_res.handshake_completed = True
    tls_res.verification_passed = True
    tls_res.chain_verified_by_ca = True
    tls_res.tls_version = "TLSv1.3"
    tls_res.cipher_name = "TLS_AES_256_GCM_SHA384"
    tls_res.cipher_bits = 256

    cert_res = CertificateAnalysisResult()
    cert_res.parsed_successfully = True
    cert_res.hostname_matched = True
    cert_res.is_valid_now = True
    cert_res.days_remaining = 20  # Under 30 days warning threshold
    cert_res.public_key_algorithm = "RSA"
    cert_res.public_key_size = 2048
    cert_res.signature_algorithm = "sha256WithRSAEncryption"
    cert_res.subject_alternative_names = ["example.com"]

    assessment = assess_security_posture(tls_res, cert_res, warn_days=30, critical_days=7)
    assert assessment.warning_count >= 1
    assert assessment.overall_outcome in ("WARNINGS", "SECURE")
    time_finding = next(f for f in assessment.findings if f.finding_id == "TIME-01")
    assert time_finding.status == "Warning"


def test_assessment_deprecated_protocol():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = True
    tls_res.handshake_completed = True
    tls_res.verification_passed = True
    tls_res.chain_verified_by_ca = True
    tls_res.tls_version = "TLSv1.0"
    tls_res.cipher_name = "AES128-SHA"
    tls_res.cipher_bits = 128

    cert_res = CertificateAnalysisResult()
    cert_res.parsed_successfully = True
    cert_res.hostname_matched = True
    cert_res.is_valid_now = True
    cert_res.days_remaining = 90
    cert_res.public_key_algorithm = "RSA"
    cert_res.public_key_size = 2048
    cert_res.signature_algorithm = "sha256WithRSAEncryption"
    cert_res.subject_alternative_names = ["example.com"]

    assessment = assess_security_posture(tls_res, cert_res)
    assert assessment.overall_outcome == "INSECURE"
    proto_finding = next(f for f in assessment.findings if f.finding_id == "PROTO-01")
    assert proto_finding.status == "Fail"
    assert proto_finding.severity == "Critical"


def test_assessment_hsts_findings():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = True
    tls_res.handshake_completed = True
    tls_res.verification_passed = True
    tls_res.chain_verified_by_ca = True
    tls_res.tls_version = "TLSv1.3"
    tls_res.cipher_name = "TLS_AES_256_GCM_SHA384"
    tls_res.hsts_evaluated = True
    tls_res.hsts_present = True
    tls_res.hsts_raw_header = "max-age=31536000; includeSubDomains"
    tls_res.hsts_max_age = 31536000

    cert_res = CertificateAnalysisResult()
    cert_res.parsed_successfully = True
    cert_res.hostname_matched = True
    cert_res.is_valid_now = True
    cert_res.days_remaining = 60
    cert_res.public_key_algorithm = "RSA"
    cert_res.public_key_size = 2048
    cert_res.signature_algorithm = "sha256WithRSAEncryption"
    cert_res.subject_alternative_names = ["example.com"]

    assessment = assess_security_posture(tls_res, cert_res)
    hsts_finding = next(f for f in assessment.findings if f.finding_id == "HSTS-01")
    assert hsts_finding.status == "Pass"
    assert "RFC 6797" in hsts_finding.reference_standard

    # When HSTS header is missing
    tls_res.hsts_present = False
    tls_res.hsts_raw_header = None
    assessment_no_hsts = assess_security_posture(tls_res, cert_res)
    hsts_warn = next(f for f in assessment_no_hsts.findings if f.finding_id == "HSTS-01")
    assert hsts_warn.status == "Warning"


def test_assessment_pfs_findings():
    tls_res = TLSConnectionResult()
    tls_res.connection_established = True
    tls_res.handshake_completed = True
    tls_res.verification_passed = True
    tls_res.chain_verified_by_ca = True
    tls_res.tls_version = "TLSv1.2"
    tls_res.cipher_name = "TLS_RSA_WITH_AES_128_CBC_SHA"  # Static RSA, no PFS

    cert_res = CertificateAnalysisResult()
    cert_res.parsed_successfully = True
    cert_res.hostname_matched = True
    cert_res.is_valid_now = True
    cert_res.days_remaining = 60
    cert_res.public_key_algorithm = "RSA"
    cert_res.public_key_size = 2048
    cert_res.signature_algorithm = "sha256WithRSAEncryption"
    cert_res.subject_alternative_names = ["example.com"]

    assessment = assess_security_posture(tls_res, cert_res)
    pfs_finding = next(f for f in assessment.findings if f.finding_id == "PFS-01")
    assert pfs_finding.status == "Fail"
    assert pfs_finding.severity == "High"

