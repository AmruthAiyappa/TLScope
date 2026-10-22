"""
Certificate Analyzer Service for TLScope.

Parses X.509 leaf certificates using the `cryptography` library.
Extracts subject, issuer, validity period, SANs, public key specifications,
signature algorithms, fingerprints, extensions, and performs RFC 6125 hostname matching.
"""

import datetime
import fnmatch
from typing import Dict, Any, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448


class CertificateAnalysisResult:
    """Structured representation of parsed certificate data."""
    def __init__(self):
        self.parsed_successfully: bool = False
        self.error: Optional[str] = None
        
        # Identity
        self.subject_dn: str = ""
        self.subject_common_name: Optional[str] = None
        self.subject_organization: Optional[str] = None
        self.subject_country: Optional[str] = None
        self.subject_attributes: Dict[str, str] = {}
        
        # Issuer
        self.issuer_dn: str = ""
        self.issuer_common_name: Optional[str] = None
        self.issuer_organization: Optional[str] = None
        self.issuer_country: Optional[str] = None
        self.issuer_attributes: Dict[str, str] = {}
        
        # Validity
        self.valid_from: Optional[datetime.datetime] = None
        self.valid_to: Optional[datetime.datetime] = None
        self.valid_from_iso: str = ""
        self.valid_to_iso: str = ""
        self.is_valid_now: bool = False
        self.is_expired: bool = False
        self.is_not_yet_valid: bool = False
        self.days_remaining: int = 0
        self.hours_remaining: int = 0
        self.total_validity_days: int = 0
        
        # Hostname Matching
        self.subject_alternative_names: List[str] = []
        self.hostname_matched: bool = False
        self.hostname_match_details: str = ""
        
        # Cryptographic Details
        self.serial_number_dec: str = ""
        self.serial_number_hex: str = ""
        self.version: str = ""
        self.signature_algorithm: str = ""
        self.signature_hash_algorithm: Optional[str] = None
        
        # Public Key
        self.public_key_algorithm: str = ""
        self.public_key_size: Optional[int] = None
        self.public_key_details: str = ""
        
        # Fingerprints
        self.fingerprint_sha256: str = ""
        self.fingerprint_sha1: str = ""
        
        # Chain & Self-Signed Detection
        self.is_self_signed: bool = False
        self.chain_hierarchy: List[Dict[str, Any]] = []

        # Extensions
        self.is_ca: bool = False
        self.path_length: Optional[int] = None
        self.key_usages: List[str] = []
        self.extended_key_usages: List[str] = []
        self.ocsp_urls: List[str] = []
        self.ca_issuer_urls: List[str] = []
        self.crl_distribution_points: List[str] = []
        self.subject_key_identifier: Optional[str] = None
        self.authority_key_identifier: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to a JSON-serializable dictionary."""
        return {
            "parsed_successfully": self.parsed_successfully,
            "error": self.error,
            "subject_dn": self.subject_dn,
            "subject_common_name": self.subject_common_name,
            "subject_organization": self.subject_organization,
            "subject_country": self.subject_country,
            "subject_attributes": self.subject_attributes,
            "issuer_dn": self.issuer_dn,
            "issuer_common_name": self.issuer_common_name,
            "issuer_organization": self.issuer_organization,
            "issuer_country": self.issuer_country,
            "issuer_attributes": self.issuer_attributes,
            "valid_from_iso": self.valid_from_iso,
            "valid_to_iso": self.valid_to_iso,
            "is_valid_now": self.is_valid_now,
            "is_expired": self.is_expired,
            "is_not_yet_valid": self.is_not_yet_valid,
            "days_remaining": self.days_remaining,
            "hours_remaining": self.hours_remaining,
            "total_validity_days": self.total_validity_days,
            "subject_alternative_names": self.subject_alternative_names,
            "hostname_matched": self.hostname_matched,
            "hostname_match_details": self.hostname_match_details,
            "serial_number_dec": self.serial_number_dec,
            "serial_number_hex": self.serial_number_hex,
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "signature_hash_algorithm": self.signature_hash_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_size": self.public_key_size,
            "public_key_details": self.public_key_details,
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_sha1": self.fingerprint_sha1,
            "is_self_signed": self.is_self_signed,
            "chain_hierarchy": self.chain_hierarchy,
            "is_ca": self.is_ca,
            "path_length": self.path_length,
            "key_usages": self.key_usages,
            "extended_key_usages": self.extended_key_usages,
            "ocsp_urls": self.ocsp_urls,
            "ca_issuer_urls": self.ca_issuer_urls,
            "crl_distribution_points": self.crl_distribution_points,
            "subject_key_identifier": self.subject_key_identifier,
            "authority_key_identifier": self.authority_key_identifier
        }


def format_hex_with_colons(byte_sequence: bytes) -> str:
    """Formats bytes as XX:XX:XX:XX hex string."""
    return ":".join(f"{b:02X}" for b in byte_sequence)


def match_hostname(hostname: str, san_list: List[str], common_name: Optional[str]) -> Tuple[bool, str]:
    """
    Evaluates whether the requested hostname matches the certificate SANs or Common Name
    following RFC 6125 (SAN takes precedence, wildcards supported in leftmost label).
    """
    target = hostname.lower()
    
    # Check SANs first (RFC 6125 preferred)
    if san_list:
        for san in san_list:
            san_lower = san.lower()
            if san_lower == target:
                return True, f"Exact match with SAN: '{san}'"
            if san_lower.startswith("*."):
                wildcard_suffix = san_lower[2:]
                # Check wildcard matching: *.example.com matches foo.example.com but not bar.foo.example.com
                if target.endswith("." + wildcard_suffix):
                    prefix = target[:-len("." + wildcard_suffix)]
                    if "." not in prefix and prefix:
                        return True, f"Wildcard match with SAN: '{san}'"
        return False, f"Hostname '{hostname}' does not match any Subject Alternative Names (SANs)."

    # Fallback to CN if no SANs present (legacy X.509)
    if common_name:
        cn_lower = common_name.lower()
        if cn_lower == target:
            return True, f"Exact match with Common Name (legacy): '{common_name}'"
        if cn_lower.startswith("*."):
            wildcard_suffix = cn_lower[2:]
            if target.endswith("." + wildcard_suffix):
                prefix = target[:-len("." + wildcard_suffix)]
                if "." not in prefix and prefix:
                    return True, f"Wildcard match with Common Name (legacy): '{common_name}'"
        return False, f"Hostname '{hostname}' does not match Common Name '{common_name}'."

    return False, "Certificate does not contain any SANs or Common Name to match against."


def analyze_peer_certificate(cert_der: Optional[bytes], requested_hostname: str) -> CertificateAnalysisResult:
    """
    Parses DER encoded X.509 certificate and returns detailed analysis.
    """
    result = CertificateAnalysisResult()
    if not cert_der:
        result.error = "No certificate DER data was provided for analysis."
        return result

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        result.error = f"Failed to parse DER certificate: {str(e)}"
        return result

    try:
        # Subject
        result.subject_dn = cert.subject.rfc4514_string()
        for attr in cert.subject:
            oid_name = attr.oid._name
            value = str(attr.value)
            result.subject_attributes[oid_name] = value
            if oid_name == "commonName":
                result.subject_common_name = value
            elif oid_name == "organizationName":
                result.subject_organization = value
            elif oid_name == "countryName":
                result.subject_country = value

        # Issuer
        result.issuer_dn = cert.issuer.rfc4514_string()
        for attr in cert.issuer:
            oid_name = attr.oid._name
            value = str(attr.value)
            result.issuer_attributes[oid_name] = value
            if oid_name == "commonName":
                result.issuer_common_name = value
            elif oid_name == "organizationName":
                result.issuer_organization = value
            elif oid_name == "countryName":
                result.issuer_country = value

        # Validity Periods (UTC)
        try:
            valid_from = cert.not_valid_before_utc
            valid_to = cert.not_valid_after_utc
        except AttributeError:
            # Fallback for older cryptography versions
            valid_from = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            valid_to = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        result.valid_from = valid_from
        result.valid_to = valid_to
        result.valid_from_iso = valid_from.strftime("%Y-%m-%d %H:%M:%S UTC")
        result.valid_to_iso = valid_to.strftime("%Y-%m-%d %H:%M:%S UTC")

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        result.is_expired = now_utc > valid_to
        result.is_not_yet_valid = now_utc < valid_from
        result.is_valid_now = (not result.is_expired) and (not result.is_not_yet_valid)

        time_remaining = valid_to - now_utc
        result.days_remaining = time_remaining.days
        result.hours_remaining = int(time_remaining.seconds // 3600)
        
        total_duration = valid_to - valid_from
        result.total_validity_days = total_duration.days

        # Serial Number & Version
        result.serial_number_dec = str(cert.serial_number)
        hex_serial = hex(cert.serial_number)[2:].upper()
        if len(hex_serial) % 2 != 0:
            hex_serial = "0" + hex_serial
        result.serial_number_hex = ":".join(hex_serial[i:i+2] for i in range(0, len(hex_serial), 2))
        result.version = f"v{cert.version.value + 1}" if hasattr(cert.version, "value") else str(cert.version)

        # Signature Algorithm
        result.signature_algorithm = cert.signature_algorithm_oid._name
        if cert.signature_hash_algorithm:
            result.signature_hash_algorithm = cert.signature_hash_algorithm.name

        # Public Key details
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            result.public_key_algorithm = "RSA"
            result.public_key_size = pub_key.key_size
            result.public_key_details = f"RSA {pub_key.key_size}-bit (e={pub_key.public_numbers().e})"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            result.public_key_algorithm = "EC"
            result.public_key_size = pub_key.curve.key_size
            result.public_key_details = f"Elliptic Curve {pub_key.curve.name} ({pub_key.curve.key_size}-bit)"
        elif isinstance(pub_key, dsa.DSAPublicKey):
            result.public_key_algorithm = "DSA"
            result.public_key_size = pub_key.key_size
            result.public_key_details = f"DSA {pub_key.key_size}-bit"
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            result.public_key_algorithm = "Ed25519"
            result.public_key_size = 256
            result.public_key_details = "Edwards-curve Digital Signature Algorithm 25519 (256-bit)"
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            result.public_key_algorithm = "Ed448"
            result.public_key_size = 448
            result.public_key_details = "Edwards-curve Digital Signature Algorithm 448 (448-bit)"
        else:
            result.public_key_algorithm = type(pub_key).__name__
            result.public_key_details = f"Algorithm: {result.public_key_algorithm}"

        # Fingerprints
        result.fingerprint_sha256 = format_hex_with_colons(cert.fingerprint(hashes.SHA256()))
        result.fingerprint_sha1 = format_hex_with_colons(cert.fingerprint(hashes.SHA1()))

        # Extensions
        # 1. Subject Alternative Names (SAN)
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    result.subject_alternative_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    result.subject_alternative_names.append(str(name.value))
        except x509.ExtensionNotFound:
            pass

        # Perform Hostname Match Evaluation
        matched, details = match_hostname(
            requested_hostname,
            result.subject_alternative_names,
            result.subject_common_name
        )
        result.hostname_matched = matched
        result.hostname_match_details = details

        # 2. Basic Constraints
        try:
            bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
            result.is_ca = bc_ext.value.ca
            result.path_length = bc_ext.value.path_length
        except x509.ExtensionNotFound:
            pass

        # 3. Key Usage
        try:
            ku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            usages = []
            ku = ku_ext.value
            if ku.digital_signature: usages.append("Digital Signature")
            if ku.content_commitment: usages.append("Content Commitment")
            if ku.key_encipherment: usages.append("Key Encipherment")
            if ku.data_encipherment: usages.append("Data Encipherment")
            if ku.key_agreement: usages.append("Key Agreement")
            if ku.key_cert_sign: usages.append("Certificate Signing")
            if ku.crl_sign: usages.append("CRL Signing")
            result.key_usages = usages
        except (x509.ExtensionNotFound, ValueError):
            pass

        # 4. Extended Key Usage
        try:
            eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
            for oid in eku_ext.value:
                result.extended_key_usages.append(oid._name)
        except x509.ExtensionNotFound:
            pass

        # 5. Authority Information Access (AIA)
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia_ext.value:
                if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    result.ocsp_urls.append(desc.access_location.value)
                elif desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    result.ca_issuer_urls.append(desc.access_location.value)
        except x509.ExtensionNotFound:
            pass

        # 6. CRL Distribution Points
        try:
            crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            result.crl_distribution_points.append(name.value)
        except x509.ExtensionNotFound:
            pass

        # 7. Subject & Authority Key Identifiers
        try:
            ski_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            result.subject_key_identifier = format_hex_with_colons(ski_ext.value.digest)
        except x509.ExtensionNotFound:
            pass

        try:
            aki_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            if aki_ext.value.key_identifier:
                result.authority_key_identifier = format_hex_with_colons(aki_ext.value.key_identifier)
        except x509.ExtensionNotFound:
            pass

        # Determine self-signed vs CA chain hierarchy
        result.is_self_signed = (cert.issuer == cert.subject)
        if result.is_self_signed:
            result.chain_hierarchy = [
                {
                    "level_name": "Self-Signed Root / Leaf",
                    "common_name": result.subject_common_name or result.subject_dn,
                    "organization": result.subject_organization or "Self-Signed",
                    "role": "SELF_SIGNED",
                    "is_ca": result.is_ca,
                    "trusted_by_system": False,
                    "description": "Certificate issuer matches subject directly. Untrusted without manual root anchor."
                }
            ]
        else:
            result.chain_hierarchy = [
                {
                    "level_name": "Root Trust Anchor",
                    "common_name": "Pre-installed Root Authority",
                    "organization": "Operating System / Mozilla NSS Trust Store",
                    "role": "ROOT_CA",
                    "is_ca": True,
                    "trusted_by_system": True,
                    "description": "Pre-distributed, unconditionally trusted cryptographic root."
                },
                {
                    "level_name": "Intermediate Certificate Authority",
                    "common_name": result.issuer_common_name or result.issuer_dn,
                    "organization": result.issuer_organization or "Intermediate Authority",
                    "role": "INTERMEDIATE_CA",
                    "is_ca": True,
                    "trusted_by_system": True,
                    "description": "Authorized issuing CA delegated by Root CA to sign end-entity certificates."
                },
                {
                    "level_name": "End-Entity (Leaf) Certificate",
                    "common_name": result.subject_common_name or result.subject_dn,
                    "organization": result.subject_organization or "Target Service Host",
                    "role": "LEAF",
                    "is_ca": result.is_ca,
                    "trusted_by_system": True,
                    "description": "Active server certificate presented during the TLS handshake."
                }
            ]

        result.parsed_successfully = True
        return result

    except Exception as e:
        result.error = f"Error during certificate field analysis: {str(e)}"
        return result
