"""
TLS Connection Inspector Service for TLScope.

Establishes genuine TLS connections to target endpoints, enforces TLS verification,
records negotiated protocol versions, cipher suites, ALPN, extracts peer certificate DER data,
and performs safe HTTP Strict Transport Security (HSTS) header auditing.
Guarantees safe socket closure, destination IP pinning, and transparent reporting of failures.
"""

import datetime
import re
import socket
import ssl
from typing import Optional, Dict, Any, List, Tuple


class TLSInspectionError(Exception):
    """Base exception for TLS inspection failures."""
    pass


class TLSConnectionResult:
    """Encapsulates the raw results and telemetry of a TLS connection attempt."""
    def __init__(self):
        self.hostname: str = ""
        self.port: int = 443
        self.pinned_ip: str = ""
        self.resolved_ips: list = []
        self.timestamp: str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Connection status & scan states
        self.scan_state: str = "PENDING"  # PENDING, RUNNING, COMPLETED, COMPLETED_WITH_WARNINGS, FAILED
        self.connection_established: bool = False
        self.handshake_completed: bool = False
        self.verification_passed: bool = False
        self.verification_error: Optional[str] = None
        self.error_category: Optional[str] = None
        
        # Connection pipeline telemetry
        self.pipeline_stages: List[Dict[str, Any]] = []
        
        # TLS parameters
        self.tls_version: Optional[str] = None
        self.cipher_name: Optional[str] = None
        self.cipher_protocol: Optional[str] = None
        self.cipher_bits: Optional[int] = None
        self.alpn_negotiated: Optional[str] = None
        self.compression: Optional[str] = None
        
        # Certificate data
        self.peer_cert_der: Optional[bytes] = None
        self.peer_cert_dict: Optional[Dict[str, Any]] = None
        self.chain_verified_by_ca: bool = False
        self.is_diagnostic_leaf: bool = False  # True if leaf extracted post-failure for inspection
        
        # HSTS Header Inspection
        self.hsts_evaluated: bool = False
        self.hsts_present: bool = False
        self.hsts_raw_header: Optional[str] = None
        self.hsts_max_age: Optional[int] = None
        self.hsts_include_subdomains: bool = False
        self.hsts_preload: bool = False
        self.hsts_eval_notes: str = ""


def inspect_tls_endpoint(
    hostname: str,
    pinned_ip: str,
    port: int = 443,
    connect_timeout: float = 6.0,
    read_timeout: float = 6.0,
    custom_ca_file: Optional[str] = None,
    check_hsts: bool = True
) -> TLSConnectionResult:
    """
    Connects to the specified endpoint using pinned_ip and executes a secure TLS handshake.
    
    Adheres strictly to security rules:
    - Verifies server identity against `hostname` via SNI and certificate SAN/CN.
    - Uses trusted CA store (or custom_ca_file for local test fixtures).
    - If certificate verification fails, reports verification failure accurately without masking.
    - If verification fails, safely extracts diagnostic leaf cert bytes so the user and
      security assessor can see why it failed (e.g. expired, self-signed, hostname mismatch).
    - Audits HSTS headers safely using pinned IP with no redirect following.
    """
    result = TLSConnectionResult()
    result.hostname = hostname
    result.pinned_ip = pinned_ip
    result.port = port
    result.scan_state = "RUNNING"

    # Stage 1: DNS & Destination IP Pinning
    result.pipeline_stages.append({
        "stage_id": "DNS_PINNING",
        "name": "DNS Resolution & SSRF IP Pinning",
        "status": "PASS",
        "details": f"Destination pinned to validated IP {pinned_ip} to prevent DNS rebinding."
    })

    # Step 1: Create verified SSL context
    verified_ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=custom_ca_file
    )
    verified_ctx.check_hostname = True
    verified_ctx.verify_mode = ssl.CERT_REQUIRED
    
    # Configure ALPN support (HTTP/2 and HTTP/1.1)
    try:
        verified_ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        pass

    raw_socket = None
    ssl_socket = None

    try:
        # Stage 2: TCP Connection
        raw_socket = socket.socket(
            socket.AF_INET6 if ":" in pinned_ip else socket.AF_INET,
            socket.SOCK_STREAM
        )
        raw_socket.settimeout(connect_timeout)
        raw_socket.connect((pinned_ip, port))
        raw_socket.settimeout(read_timeout)
        result.connection_established = True
        
        result.pipeline_stages.append({
            "stage_id": "TCP_CONNECT",
            "name": "TCP Socket Connect",
            "status": "PASS",
            "details": f"Successfully connected to {pinned_ip}:{port} within {connect_timeout}s timeout."
        })

        # Stage 3: TLS Handshake & SNI
        ssl_socket = verified_ctx.wrap_socket(
            raw_socket,
            server_hostname=hostname,
            do_handshake_on_connect=True
        )

        result.handshake_completed = True
        result.verification_passed = True
        result.chain_verified_by_ca = True
        result.scan_state = "COMPLETED"

        # Extract negotiated parameters
        result.tls_version = ssl_socket.version()
        cipher_info = ssl_socket.cipher()
        if cipher_info:
            result.cipher_name = cipher_info[0]
            result.cipher_protocol = cipher_info[1]
            result.cipher_bits = cipher_info[2]
            
        try:
            result.alpn_negotiated = ssl_socket.selected_alpn_protocol()
        except (AttributeError, ssl.SSLError):
            result.alpn_negotiated = None

        result.compression = ssl_socket.compression()
        
        # Peer certificate
        result.peer_cert_der = ssl_socket.getpeercert(binary_form=True)
        result.peer_cert_dict = ssl_socket.getpeercert()

        result.pipeline_stages.append({
            "stage_id": "TLS_HANDSHAKE",
            "name": "TLS Session Handshake",
            "status": "PASS",
            "details": f"Negotiated {result.tls_version} using {result.cipher_name} ({result.cipher_bits}-bit)."
        })

        result.pipeline_stages.append({
            "stage_id": "CERT_VALIDATION",
            "name": "CA Trust Chain Verification",
            "status": "PASS",
            "details": "Peer certificate chain verified successfully against trusted CA store."
        })

        # Stage 4: Safe HTTP HSTS Header Inspection (Optional probe)
        if check_hsts:
            _probe_hsts_security_header(hostname, pinned_ip, port, read_timeout, result)

        return result

    except ssl.SSLCertVerificationError as e:
        # Certificate or Hostname verification failed
        result.connection_established = True
        result.handshake_completed = False
        result.verification_passed = False
        result.chain_verified_by_ca = False
        result.scan_state = "FAILED_VERIFICATION"
        result.verification_error = f"Certificate Verification Failed: {e.verify_message if hasattr(e, 'verify_message') else str(e)}"
        result.error_category = "CERT_VERIFY_ERROR"

        result.pipeline_stages.append({
            "stage_id": "TCP_CONNECT",
            "name": "TCP Socket Connect",
            "status": "PASS",
            "details": f"Connected to {pinned_ip}:{port}."
        })
        result.pipeline_stages.append({
            "stage_id": "TLS_HANDSHAKE",
            "name": "TLS Session Handshake",
            "status": "FAIL",
            "details": f"Handshake halted by client trust verification: {result.verification_error}"
        })
        result.pipeline_stages.append({
            "stage_id": "CERT_VALIDATION",
            "name": "CA Trust Chain Verification",
            "status": "FAIL",
            "details": "Certificate signature chain could not be verified against trusted authorities."
        })

        # Safely retrieve leaf certificate in diagnostic mode so user can see why it failed
        _fetch_diagnostic_certificate(hostname, pinned_ip, port, connect_timeout, result)
        
        result.pipeline_stages.append({
            "stage_id": "HTTP_HSTS",
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "NOT_EVALUATED",
            "details": "HSTS header could not be evaluated due to TLS certificate verification failure."
        })
        return result

    except ssl.SSLError as e:
        # TLS protocol error, cipher handshake error, unsupported version, etc.
        result.connection_established = True if result.connection_established else False
        result.handshake_completed = False
        result.verification_passed = False
        result.scan_state = "FAILED_HANDSHAKE"
        result.verification_error = f"TLS Handshake Error: {str(e)}"
        result.error_category = "TLS_HANDSHAKE_ERROR"

        if result.connection_established:
            result.pipeline_stages.append({
                "stage_id": "TCP_CONNECT",
                "name": "TCP Socket Connect",
                "status": "PASS",
                "details": f"Connected to {pinned_ip}:{port}."
            })
        result.pipeline_stages.append({
            "stage_id": "TLS_HANDSHAKE",
            "name": "TLS Session Handshake",
            "status": "FAIL",
            "details": f"TLS handshake failed: {str(e)}"
        })
        result.pipeline_stages.append({
            "stage_id": "CERT_VALIDATION",
            "name": "CA Trust Chain Verification",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: Handshake was not completed."
        })
        result.pipeline_stages.append({
            "stage_id": "HTTP_HSTS",
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: Handshake was not completed."
        })
        return result

    except (socket.timeout, TimeoutError):
        result.connection_established = False
        result.handshake_completed = False
        result.verification_passed = False
        result.scan_state = "FAILED_CONNECTION"
        result.verification_error = f"Connection timed out while attempting to reach {hostname}:{port} ({pinned_ip}) within {connect_timeout}s."
        result.error_category = "TIMEOUT_ERROR"

        result.pipeline_stages.append({
            "stage_id": "TCP_CONNECT",
            "name": "TCP Socket Connect",
            "status": "FAIL",
            "details": f"Socket connect to {pinned_ip}:{port} timed out after {connect_timeout} seconds."
        })
        result.pipeline_stages.append({
            "stage_id": "TLS_HANDSHAKE",
            "name": "TLS Session Handshake",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: TCP connection could not be established."
        })
        result.pipeline_stages.append({
            "stage_id": "CERT_VALIDATION",
            "name": "CA Trust Chain Verification",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: TCP connection could not be established."
        })
        result.pipeline_stages.append({
            "stage_id": "HTTP_HSTS",
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: TCP connection could not be established."
        })
        return result

    except ConnectionRefusedError:
        result.connection_established = False
        result.handshake_completed = False
        result.verification_passed = False
        result.scan_state = "FAILED_CONNECTION"
        result.verification_error = f"Connection refused by target {hostname}:{port} ({pinned_ip}). Port may be closed or filtered by firewall."
        result.error_category = "CONNECTION_REFUSED"

        result.pipeline_stages.append({
            "stage_id": "TCP_CONNECT",
            "name": "TCP Socket Connect",
            "status": "FAIL",
            "details": f"TCP connection actively refused by {pinned_ip}:{port}."
        })
        result.pipeline_stages.append({
            "stage_id": "TLS_HANDSHAKE",
            "name": "TLS Session Handshake",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: Port is closed or unreachable."
        })
        result.pipeline_stages.append({
            "stage_id": "CERT_VALIDATION",
            "name": "CA Trust Chain Verification",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: Port is closed or unreachable."
        })
        result.pipeline_stages.append({
            "stage_id": "HTTP_HSTS",
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "NOT_EVALUATED",
            "details": "Unavailable: Port is closed or unreachable."
        })
        return result

    except OSError as e:
        result.connection_established = False
        result.handshake_completed = False
        result.verification_passed = False
        result.scan_state = "FAILED_CONNECTION"
        result.verification_error = f"Network operating system error ({e.errno or 'Unknown'}): {e.strerror or str(e)}"
        result.error_category = "NETWORK_ERROR"

        result.pipeline_stages.append({
            "stage_id": "TCP_CONNECT",
            "name": "TCP Socket Connect",
            "status": "FAIL",
            "details": f"OS network socket failure: {e.strerror or str(e)}"
        })
        result.pipeline_stages.append({
            "stage_id": "TLS_HANDSHAKE",
            "name": "TLS Session Handshake",
            "status": "NOT_EVALUATED",
            "details": "Unavailable due to network failure."
        })
        result.pipeline_stages.append({
            "stage_id": "CERT_VALIDATION",
            "name": "CA Trust Chain Verification",
            "status": "NOT_EVALUATED",
            "details": "Unavailable due to network failure."
        })
        result.pipeline_stages.append({
            "stage_id": "HTTP_HSTS",
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "NOT_EVALUATED",
            "details": "Unavailable due to network failure."
        })
        return result

    finally:
        if ssl_socket:
            try:
                ssl_socket.close()
            except Exception:
                pass
        elif raw_socket:
            try:
                raw_socket.close()
            except Exception:
                pass


def _probe_hsts_security_header(
    hostname: str,
    pinned_ip: str,
    port: int,
    timeout: float,
    result: TLSConnectionResult
) -> None:
    """
    Safely probes for HTTP Strict Transport Security (HSTS, RFC 6797) header.
    Connects only to the pinned IP with SNI, sends HEAD request without following redirects.
    """
    raw_sock = None
    ssl_sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        raw_sock = socket.socket(
            socket.AF_INET6 if ":" in pinned_ip else socket.AF_INET,
            socket.SOCK_STREAM
        )
        raw_sock.settimeout(min(timeout, 3.5))
        raw_sock.connect((pinned_ip, port))
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)

        # Transmit standard HTTP HEAD request
        request_data = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"User-Agent: TLScope-Audit/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        ssl_sock.sendall(request_data)

        # Read response headers up to 8KB
        response_bytes = b""
        while len(response_bytes) < 8192:
            chunk = ssl_sock.recv(2048)
            if not chunk:
                break
            response_bytes += chunk
            if b"\r\n\r\n" in response_bytes:
                break

        response_str = response_bytes.decode("latin-1", errors="replace")
        headers_section = response_str.split("\r\n\r\n")[0]
        
        result.hsts_evaluated = True

        for line in headers_section.split("\r\n"):
            if line.lower().startswith("strict-transport-security:"):
                header_value = line.split(":", 1)[1].strip()
                result.hsts_present = True
                result.hsts_raw_header = header_value

                # Parse max-age
                max_age_match = re.search(r"max-age=(\d+)", header_value, re.IGNORECASE)
                if max_age_match:
                    result.hsts_max_age = int(max_age_match.group(1))

                result.hsts_include_subdomains = "includesubdomains" in header_value.lower()
                result.hsts_preload = "preload" in header_value.lower()
                break

        if result.hsts_present:
            result.pipeline_stages.append({
                "stage_id": "HTTP_HSTS",
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "PASS",
                "details": f"HSTS header observed: {result.hsts_raw_header} (max-age={result.hsts_max_age}s)"
            })
        else:
            result.pipeline_stages.append({
                "stage_id": "HTTP_HSTS",
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "WARN",
                "details": "No Strict-Transport-Security header detected on default root endpoint."
            })

    except Exception as e:
        result.hsts_evaluated = False
        result.hsts_eval_notes = f"HSTS probe inconclusive: {str(e)}"
        result.pipeline_stages.append({
            "stage_id": "HTTP_HSTS",
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "NOT_EVALUATED",
            "details": f"Probe inconclusive or server closed connection: {str(e)}"
        })
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass


def _fetch_diagnostic_certificate(
    hostname: str,
    pinned_ip: str,
    port: int,
    timeout: float,
    result: TLSConnectionResult
) -> None:
    """
    Safely captures the peer certificate DER for post-failure diagnostics.
    NOTE: Does NOT change result.verification_passed. It remains False.
    """
    raw_sock = None
    ssl_sock = None
    try:
        diag_ctx = ssl._create_unverified_context()
        raw_sock = socket.socket(
            socket.AF_INET6 if ":" in pinned_ip else socket.AF_INET,
            socket.SOCK_STREAM
        )
        raw_sock.settimeout(timeout)
        raw_sock.connect((pinned_ip, port))
        
        ssl_sock = diag_ctx.wrap_socket(raw_sock, server_hostname=hostname)
        result.peer_cert_der = ssl_sock.getpeercert(binary_form=True)
        result.tls_version = ssl_sock.version()
        cipher_info = ssl_sock.cipher()
        if cipher_info:
            result.cipher_name = cipher_info[0]
            result.cipher_protocol = cipher_info[1]
            result.cipher_bits = cipher_info[2]
        result.is_diagnostic_leaf = True
    except Exception:
        # Diagnostic retrieval is best-effort
        pass
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass
