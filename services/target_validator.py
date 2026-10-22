"""
Target Validation & SSRF Prevention Service for TLScope.

Normalizes user inputs, validates RFC compliant hostnames, enforces port constraints,
and validates resolved IP addresses to protect against Server-Side Request Forgery (SSRF)
and DNS rebinding attacks.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Optional


class TargetValidationError(Exception):
    """Raised when target hostname or port fails validation or security checks."""
    pass


# Carrier Grade NAT range: 100.64.0.0/10
CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")
# IPv4 broadcast: 255.255.255.255/32
IPV4_BROADCAST = ipaddress.ip_network("255.255.255.255/32")


def is_prohibited_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address belongs to a prohibited/private/internal range.
    Returns (is_prohibited, reason).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    # Handle IPv6 mapped IPv4 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, f"Loopback address ({ip}) is prohibited to prevent SSRF."
    if ip.is_private:
        return True, f"Private network address ({ip}) is prohibited to prevent SSRF."
    if ip.is_link_local:
        return True, f"Link-local address ({ip}) is prohibited to prevent SSRF."
    if ip.is_multicast:
        return True, f"Multicast address ({ip}) is prohibited."
    if ip.is_reserved:
        return True, f"Reserved address ({ip}) is prohibited."
    if ip.is_unspecified:
        return True, f"Unspecified address ({ip}) is prohibited."

    if isinstance(ip, ipaddress.IPv4Address):
        if ip in CARRIER_GRADE_NAT:
            return True, f"Carrier-Grade NAT address ({ip}) is prohibited."
        if ip in IPV4_BROADCAST:
            return True, f"Broadcast address ({ip}) is prohibited."

    return False, ""


def normalize_and_parse_target(raw_input: str, default_port: int = 443) -> Tuple[str, int]:
    """
    Extracts hostname and port from user input.
    Accepts hostnames (example.com), full URLs (https://example.com/path), or host:port.
    Rejects malformed inputs, unsupported schemes, embedded credentials, and invalid ports.
    """
    if not raw_input or not isinstance(raw_input, str):
        raise TargetValidationError("No target hostname provided.")

    target = raw_input.strip()
    if not target:
        raise TargetValidationError("Target cannot be empty or blank.")

    if len(target) > 512:
        raise TargetValidationError("Target string exceeds maximum allowable length (512 characters).")

    # Reject dangerous control characters or command injection attempts
    if any(ch in target for ch in ["\n", "\r", "\t", "\0", ";", "|", "&", "`", "$", "<", ">", '"', "'", " "]):
        raise TargetValidationError("Input contains invalid characters or command delimiters.")

    # Check for URI schemes
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme.lower() not in ("https", "http"):
            raise TargetValidationError(f"Unsupported URI scheme '{parsed.scheme}'. Only HTTPS/TLS targets are analyzed.")
        if parsed.username or parsed.password:
            raise TargetValidationError("Embedded user credentials in target are prohibited for security.")
        
        hostname = parsed.hostname
        port = parsed.port if parsed.port is not None else default_port
    else:
        # Check for host:port format
        # If IPv6 literal like [::1]:443
        if target.startswith("["):
            end_bracket = target.find("]")
            if end_bracket == -1:
                raise TargetValidationError("Malformed IPv6 literal address.")
            hostname = target[1:end_bracket]
            remainder = target[end_bracket+1:]
            if remainder.startswith(":"):
                try:
                    port = int(remainder[1:])
                except ValueError:
                    raise TargetValidationError("Invalid port number specified.")
            else:
                port = default_port
        elif ":" in target and not target.count(":") > 1: # Single colon means host:port
            parts = target.split(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                raise TargetValidationError("Invalid port number specified.")
        else:
            hostname = target
            port = default_port

    if not hostname:
        raise TargetValidationError("Could not parse a valid hostname from the input.")

    # Enforce port validity
    if not (1 <= port <= 65535):
        raise TargetValidationError(f"Port {port} is out of valid range (1 - 65535).")

    # Hostname syntax validation
    hostname = hostname.strip().lower()
    
    # Strip any trailing dot for FQDN normalization
    if hostname.endswith(".") and len(hostname) > 1:
        hostname = hostname[:-1]

    # Convert IDN to punycode
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetValidationError(f"Invalid internationalized domain name: {hostname}")

    # Check if input is a raw IP literal
    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if not is_ip_literal:
        # Hostname syntax verification RFC 1123
        if len(ascii_hostname) > 253:
            raise TargetValidationError("Hostname exceeds maximum allowable length of 253 characters.")

        if ".." in ascii_hostname:
            raise TargetValidationError("Hostname contains consecutive dots.")

        labels = ascii_hostname.split(".")
        if len(labels) < 2 and ascii_hostname != "localhost":
            raise TargetValidationError(f"Hostname '{hostname}' must contain a valid domain and TLD.")

        hostname_regex = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
        for label in labels:
            if not label:
                raise TargetValidationError("Hostname contains empty label.")
            if len(label) > 63:
                raise TargetValidationError(f"Hostname label '{label}' exceeds maximum length of 63 characters.")
            if not hostname_regex.match(label):
                raise TargetValidationError(f"Hostname label '{label}' contains invalid characters.")

    return ascii_hostname, port


def resolve_and_validate_target(
    hostname: str, 
    port: int, 
    allow_private_ips: bool = False
) -> Tuple[str, List[str]]:
    """
    Resolves the hostname using DNS and inspects every resolved IP against SSRF rules.
    Returns:
        (pinned_ip, all_resolved_ips)
    where pinned_ip is the selected IP address that must be used for the direct socket connection
    to prevent DNS rebinding (TOCTOU) attacks.
    """
    try:
        addr_info = socket.getaddrinfo(
            hostname, 
            port, 
            socket.AF_UNSPEC, 
            socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise TargetValidationError(f"DNS resolution failed for '{hostname}': {e.strerror or 'Name not found'}")
    except Exception as e:
        raise TargetValidationError(f"DNS lookup error for '{hostname}': {str(e)}")

    if not addr_info:
        raise TargetValidationError(f"No IP addresses could be resolved for '{hostname}'.")

    resolved_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_addr = sockaddr[0]
        if ip_addr not in resolved_ips:
            resolved_ips.append(ip_addr)

    # Validate each resolved IP address against SSRF rules
    for ip_addr in resolved_ips:
        prohibited, reason = is_prohibited_ip(ip_addr)
        if prohibited:
            if not allow_private_ips:
                raise TargetValidationError(
                    f"Security restriction: Target '{hostname}' resolves to restricted IP {ip_addr}. {reason}"
                )

    # Select the first resolved IP as the pinned destination IP
    # (Prefer IPv4 for maximum socket compatibility, or fallback to first)
    ipv4_list = [ip for ip in resolved_ips if ":" not in ip]
    pinned_ip = ipv4_list[0] if ipv4_list else resolved_ips[0]

    return pinned_ip, resolved_ips
