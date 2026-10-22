"""
Tests for TLS Inspector Service.
"""

import socket
import ssl
from unittest.mock import patch, MagicMock
from services.tls_inspector import inspect_tls_endpoint, TLSConnectionResult


def test_inspect_connection_timeout():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        mock_sock_cls.return_value = mock_sock

        res = inspect_tls_endpoint("slow.example.com", "93.184.216.34", 443, connect_timeout=0.1)
        assert res.connection_established is False
        assert res.handshake_completed is False
        assert res.verification_passed is False
        assert res.error_category == "TIMEOUT_ERROR"


def test_inspect_connection_refused():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")
        mock_sock_cls.return_value = mock_sock

        res = inspect_tls_endpoint("closed.example.com", "93.184.216.34", 443)
        assert res.connection_established is False
        assert res.error_category == "CONNECTION_REFUSED"


def test_inspect_cert_verification_failure():
    with patch("socket.socket") as mock_sock_cls, \
         patch("ssl.create_default_context") as mock_ctx_cls:
        
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock

        mock_ctx = MagicMock()
        # Simulate SSLCertVerificationError
        verify_err = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired")
        mock_ctx.wrap_socket.side_effect = verify_err
        mock_ctx_cls.return_value = mock_ctx

        res = inspect_tls_endpoint("expired.example.com", "93.184.216.34", 443)
        assert res.connection_established is True
        assert res.handshake_completed is False
        assert res.verification_passed is False
        assert res.error_category == "CERT_VERIFY_ERROR"
        assert "certificate has expired" in res.verification_error
