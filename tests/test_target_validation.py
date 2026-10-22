"""
Tests for Target Validation and SSRF Prevention Service.
"""

import pytest
from unittest.mock import patch
import socket
from services.target_validator import (
    normalize_and_parse_target,
    resolve_and_validate_target,
    is_prohibited_ip,
    TargetValidationError
)


def test_normalize_valid_hostnames():
    host, port = normalize_and_parse_target("example.com")
    assert host == "example.com"
    assert port == 443

    host, port = normalize_and_parse_target("sub.domain.co.uk:8443")
    assert host == "sub.domain.co.uk"
    assert port == 8443

    host, port = normalize_and_parse_target("https://secure.site.com/path?query=1#hash")
    assert host == "secure.site.com"
    assert port == 443


def test_reject_unsupported_schemes():
    with pytest.raises(TargetValidationError) as exc:
        normalize_and_parse_target("ftp://ftp.example.com")
    assert "Unsupported URI scheme" in str(exc.value)

    with pytest.raises(TargetValidationError) as exc:
        normalize_and_parse_target("file:///etc/passwd")
    assert "Unsupported URI scheme" in str(exc.value)


def test_reject_embedded_credentials():
    with pytest.raises(TargetValidationError) as exc:
        normalize_and_parse_target("https://admin:secret123@example.com")
    assert "Embedded user credentials" in str(exc.value)


def test_reject_command_injection_and_invalid_chars():
    invalid_inputs = [
        "example.com; rm -rf /",
        "example.com | cat /etc/passwd",
        "example.com`whoami`",
        "example.com\n127.0.0.1",
        "example.com$USER",
        "example.com<script>",
        "example .com"
    ]
    for bad in invalid_inputs:
        with pytest.raises(TargetValidationError):
            normalize_and_parse_target(bad)


def test_invalid_ports():
    with pytest.raises(TargetValidationError) as exc:
        normalize_and_parse_target("example.com:70000")
    assert "out of valid range" in str(exc.value)

    with pytest.raises(TargetValidationError) as exc:
        normalize_and_parse_target("example.com:abc")
    assert "Invalid port number" in str(exc.value)


def test_ssrf_prohibited_ips():
    # Loopback
    prohibited, _ = is_prohibited_ip("127.0.0.1")
    assert prohibited is True

    prohibited, _ = is_prohibited_ip("::1")
    assert prohibited is True

    # Private ranges
    prohibited, _ = is_prohibited_ip("10.1.2.3")
    assert prohibited is True

    prohibited, _ = is_prohibited_ip("192.168.1.50")
    assert prohibited is True

    prohibited, _ = is_prohibited_ip("172.16.5.10")
    assert prohibited is True

    # Link-local / Cloud metadata endpoint
    prohibited, _ = is_prohibited_ip("169.254.169.254")
    assert prohibited is True

    # Carrier-grade NAT
    prohibited, _ = is_prohibited_ip("100.64.0.1")
    assert prohibited is True

    # IPv4-mapped IPv6 loopback
    prohibited, _ = is_prohibited_ip("::ffff:127.0.0.1")
    assert prohibited is True

    # Public valid IP
    prohibited, _ = is_prohibited_ip("93.184.216.34")
    assert prohibited is False


def test_dns_resolution_failure():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        with pytest.raises(TargetValidationError) as exc:
            resolve_and_validate_target("nonexistent.invalid.domain.test", 443)
        assert "DNS resolution failed" in str(exc.value)


def test_ssrf_blocking_during_dns_resolution():
    # Host resolves to private IP
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(TargetValidationError) as exc:
            resolve_and_validate_target("evil.internal", 443, allow_private_ips=False)
        assert "resolves to restricted IP" in str(exc.value)


def test_pinned_ip_selection():
    # Host resolves to multiple public IPs
    mock_addrinfo = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::6810:85e5", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.133.229", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.132.229", 443))
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        pinned, all_ips = resolve_and_validate_target("example.com", 443, allow_private_ips=False)
        # Should prefer IPv4 for pinned IP
        assert pinned == "104.16.133.229"
        assert len(all_ips) == 3
