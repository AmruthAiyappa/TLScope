"""
Tests for Certificate Analysis Service.
"""

import datetime
from cryptography.hazmat.primitives import serialization
from test_fixtures.cert_factory import (
    generate_test_ca, generate_leaf_cert, generate_self_signed_cert
)
from services.certificate_analyzer import (
    analyze_peer_certificate, match_hostname, format_hex_with_colons
)


def test_analyze_valid_certificate():
    ca_key, ca_cert = generate_test_ca()
    _, leaf_cert = generate_leaf_cert(
        ca_key, ca_cert,
        common_name="securesite.local",
        san_dns_names=["securesite.local", "www.securesite.local"]
    )
    der_bytes = leaf_cert.public_bytes(serialization.Encoding.DER)
    
    result = analyze_peer_certificate(der_bytes, "securesite.local")
    assert result.parsed_successfully is True
    assert result.subject_common_name == "securesite.local"
    assert result.issuer_common_name == "TLScope Root CA"
    assert result.hostname_matched is True
    assert "Exact match with SAN" in result.hostname_match_details
    assert result.is_valid_now is True
    assert result.is_expired is False
    assert result.public_key_algorithm == "RSA"
    assert result.public_key_size == 2048
    assert "securesite.local" in result.subject_alternative_names
    assert "www.securesite.local" in result.subject_alternative_names
    assert len(result.fingerprint_sha256) > 0


def test_analyze_expired_certificate():
    ca_key, ca_cert = generate_test_ca()
    _, expired_leaf = generate_leaf_cert(
        ca_key, ca_cert,
        common_name="expired.local",
        san_dns_names=["expired.local"],
        expired=True
    )
    der_bytes = expired_leaf.public_bytes(serialization.Encoding.DER)
    
    result = analyze_peer_certificate(der_bytes, "expired.local")
    assert result.parsed_successfully is True
    assert result.is_expired is True
    assert result.is_valid_now is False
    assert result.days_remaining < 0


def test_hostname_matching_rfc6125():
    # Exact SAN match
    matched, _ = match_hostname("api.example.com", ["api.example.com"], "example.com")
    assert matched is True

    # Wildcard SAN match
    matched, _ = match_hostname("sub.example.com", ["*.example.com"], None)
    assert matched is True

    # Deep subdomains should NOT match single-level wildcard
    matched, _ = match_hostname("deep.sub.example.com", ["*.example.com"], None)
    assert matched is False

    # Hostname mismatch
    matched, details = match_hostname("attacker.com", ["legit.com"], "legit.com")
    assert matched is False
    assert "does not match" in details


def test_missing_or_corrupt_certificate_der():
    result = analyze_peer_certificate(None, "example.com")
    assert result.parsed_successfully is False
    assert "No certificate DER data" in result.error

    result_corrupt = analyze_peer_certificate(b"corrupted_invalid_der_data", "example.com")
    assert result_corrupt.parsed_successfully is False
    assert "Failed to parse DER" in result_corrupt.error


def test_certificate_chain_hierarchy_and_self_signed():
    ca_key, ca_cert = generate_test_ca()
    _, leaf_cert = generate_leaf_cert(ca_key, ca_cert, common_name="site.local")
    der_leaf = leaf_cert.public_bytes(serialization.Encoding.DER)

    res_leaf = analyze_peer_certificate(der_leaf, "site.local")
    assert res_leaf.is_self_signed is False
    assert len(res_leaf.chain_hierarchy) == 3
    assert res_leaf.chain_hierarchy[0]["role"] == "ROOT_CA"
    assert res_leaf.chain_hierarchy[1]["role"] == "INTERMEDIATE_CA"
    assert res_leaf.chain_hierarchy[2]["role"] == "LEAF"

    # Self signed certificate
    _, self_cert = generate_self_signed_cert(common_name="untrusted.local")
    der_self = self_cert.public_bytes(serialization.Encoding.DER)
    res_self = analyze_peer_certificate(der_self, "untrusted.local")
    assert res_self.is_self_signed is True
    assert len(res_self.chain_hierarchy) == 1
    assert res_self.chain_hierarchy[0]["role"] == "SELF_SIGNED"
    assert res_self.chain_hierarchy[0]["trusted_by_system"] is False

