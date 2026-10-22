"""
Integration and Web Route Tests for TLScope Flask Application.
"""

import json
import pytest
from unittest.mock import patch
from app import create_app
from config import TestConfig
from services.tls_inspector import TLSConnectionResult
from services.certificate_analyzer import CertificateAnalysisResult


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.test_client() as client:
        yield client


def test_index_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"TLScope" in res.data
    assert b"Deep HTTPS &amp; TLS Security Inspection" in res.data or b"Deep HTTPS & TLS Security Inspection" in res.data


def test_history_route(client):
    res = client.get("/history")
    assert res.status_code == 200
    assert b"Scan Audit History" in res.data


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "TLScope"


def test_security_headers_enforcement(client):
    res = client.get("/")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in res.headers


def test_scan_api_validation_error(client):
    # Empty target
    res = client.post("/api/scan", json={"target": ""})
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False


def test_scan_api_ssrf_blocked(client):
    # Prohibited loopback target with allow_private_ips = False
    with patch("app.resolve_and_validate_target") as mock_resolve:
        from services.target_validator import TargetValidationError
        mock_resolve.side_effect = TargetValidationError("Security restriction: Target resolves to restricted IP 127.0.0.1")
        
        res = client.post("/api/scan", json={"target": "127.0.0.1"})
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "restricted IP" in data["error"]


def test_scan_api_success_and_retrieval(client):
    # Mock network interactions to test complete end-to-end flow deterministically
    mock_tls = TLSConnectionResult()
    mock_tls.hostname = "example.com"
    mock_tls.pinned_ip = "93.184.216.34"
    mock_tls.port = 443
    mock_tls.connection_established = True
    mock_tls.handshake_completed = True
    mock_tls.verification_passed = True
    mock_tls.chain_verified_by_ca = True
    mock_tls.tls_version = "TLSv1.3"
    mock_tls.cipher_name = "TLS_AES_256_GCM_SHA384"
    mock_tls.cipher_bits = 256

    mock_cert = CertificateAnalysisResult()
    mock_cert.parsed_successfully = True
    mock_cert.subject_common_name = "example.com"
    mock_cert.issuer_common_name = "DigiCert Root CA"
    mock_cert.hostname_matched = True
    mock_cert.hostname_match_details = "Exact match with SAN"
    mock_cert.is_valid_now = True
    mock_cert.days_remaining = 60
    mock_cert.public_key_algorithm = "RSA"
    mock_cert.public_key_size = 2048
    mock_cert.signature_algorithm = "sha256WithRSAEncryption"
    mock_cert.subject_alternative_names = ["example.com"]

    with patch("app.resolve_and_validate_target", return_value=("93.184.216.34", ["93.184.216.34"])), \
         patch("app.inspect_tls_endpoint", return_value=mock_tls), \
         patch("app.analyze_peer_certificate", return_value=mock_cert):

        res = client.post("/api/scan", json={"target": "example.com"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        scan_id = data["scan_id"]
        assert "redirect_url" in data

        # Test view scan page
        view_res = client.get(f"/scan/{scan_id}")
        assert view_res.status_code == 200
        assert b"example.com" in view_res.data
        assert b"TLS_AES_256_GCM_SHA384" in view_res.data

        # Test download PDF
        pdf_res = client.get(f"/api/scan/{scan_id}/pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.mimetype == "application/pdf"
        assert pdf_res.data.startswith(b"%PDF-")


def test_clear_history_api(client):
    res = client.post("/api/history/clear")
    assert res.status_code == 200
    assert res.get_json()["success"] is True


def test_404_handling(client):
    res = client.get("/nonexistent-page")
    assert res.status_code == 404
    assert b"404" in res.data


def test_pki_guide_route(client):
    res = client.get("/pki-guide")
    assert res.status_code == 200
    assert b"Public Key Infrastructure" in res.data
    assert b"RFC 8446" in res.data


def test_history_stats_api(client):
    res = client.get("/api/history/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_scans" in data
    assert "secure_count" in data


def test_delete_individual_scan_api(client):
    # Save a mock scan first
    mock_tls = TLSConnectionResult()
    mock_tls.hostname = "deletetest.example.com"
    mock_tls.pinned_ip = "93.184.216.34"
    mock_tls.connection_established = True
    mock_tls.verification_passed = True
    mock_tls.chain_verified_by_ca = True
    mock_tls.tls_version = "TLSv1.3"
    mock_tls.cipher_name = "TLS_AES_256_GCM_SHA384"

    mock_cert = CertificateAnalysisResult()
    mock_cert.parsed_successfully = True
    mock_cert.hostname_matched = True
    mock_cert.is_valid_now = True
    mock_cert.public_key_algorithm = "RSA"
    mock_cert.public_key_size = 2048
    mock_cert.signature_algorithm = "sha256WithRSAEncryption"

    with patch("app.resolve_and_validate_target", return_value=("93.184.216.34", ["93.184.216.34"])), \
         patch("app.inspect_tls_endpoint", return_value=mock_tls), \
         patch("app.analyze_peer_certificate", return_value=mock_cert):

        res = client.post("/api/scan", json={"target": "deletetest.example.com"})
        scan_id = res.get_json()["scan_id"]

        # Delete the scan
        del_res = client.post(f"/api/scan/{scan_id}/delete")
        assert del_res.status_code == 200
        assert del_res.get_json()["success"] is True

        # Check that it's no longer found
        view_res = client.get(f"/scan/{scan_id}")
        assert view_res.status_code == 404

