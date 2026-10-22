"""
Security Assessor Service for TLScope.

Evaluates TLS inspection telemetry and certificate parameters against deterministic,
standards-based security rules (RFC 8446, RFC 5280, RFC 6125, RFC 6797, NIST SP 800-52r2, CA/Browser Forum).
Generates transparent, evidence-backed findings with actionable remediation advice
and an educational security score.
"""

import datetime
from typing import List, Dict, Any, Optional
from services.tls_inspector import TLSConnectionResult
from services.certificate_analyzer import CertificateAnalysisResult


class SecurityFinding:
    """Represents an individual security finding with standard reference metadata."""
    def __init__(
        self,
        finding_id: str,
        title: str,
        severity: str,       # "Informational", "Low", "Medium", "High", "Critical"
        status: str,         # "Pass", "Warning", "Fail", "Not Evaluated"
        evidence: str,
        implication: str,
        recommendation: str,
        reference_standard: str = "NIST SP 800-52r2",
        evidence_available: bool = True
    ):
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.status = status
        self.evidence = evidence
        self.implication = implication
        self.recommendation = recommendation
        self.reference_standard = reference_standard
        self.evidence_available = evidence_available
        self.evaluation_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding to dictionary with consistent result states."""
        # Standardized uppercase result state: PASS, WARN, FAIL, NOT_EVALUATED
        if self.status in ("Pass", "PASS"):
            result_state = "PASS"
        elif self.status in ("Warning", "WARN"):
            result_state = "WARN"
        elif self.status in ("Fail", "FAIL"):
            result_state = "FAIL"
        else:
            result_state = "NOT_EVALUATED"

        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "result_state": result_state,
            "evidence": self.evidence,
            "implication": self.implication,
            "recommendation": self.recommendation,
            "reference_standard": self.reference_standard,
            "evidence_available": self.evidence_available,
            "evaluation_timestamp": self.evaluation_timestamp
        }


class SecurityAssessmentResult:
    """Contains overall evaluation, findings list, and educational score."""
    def __init__(self):
        self.overall_outcome: str = "UNKNOWN"  # SECURE, WARNINGS, INSECURE, FAILED
        self.educational_score: Optional[int] = None
        self.score_label: str = "N/A"
        self.score_breakdown: List[str] = []
        self.findings: List[SecurityFinding] = []
        
        # Summary counters
        self.passed_count: int = 0
        self.warning_count: int = 0
        self.failure_count: int = 0
        self.not_assessed_count: int = 0
        
        self.timestamp: str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.assessment_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_outcome": self.overall_outcome,
            "educational_score": self.educational_score,
            "score_label": self.score_label,
            "score_breakdown": self.score_breakdown,
            "findings": [f.to_dict() for f in self.findings],
            "passed_count": self.passed_count,
            "warning_count": self.warning_count,
            "failure_count": self.failure_count,
            "not_assessed_count": self.not_assessed_count,
            "timestamp": self.timestamp,
            "assessment_notes": self.assessment_notes
        }


def assess_security_posture(
    tls_result: TLSConnectionResult,
    cert_result: CertificateAnalysisResult,
    warn_days: int = 30,
    critical_days: int = 7
) -> SecurityAssessmentResult:
    """
    Executes deterministic security rule evaluation.
    Evaluates connection, trust chain, hostname verification, temporal validity,
    cryptographic primitives, protocol versions, forward secrecy, and HSTS.
    """
    assessment = SecurityAssessmentResult()
    findings: List[SecurityFinding] = []

    # Rule 1: Connection & TCP Socket Establishment
    if not tls_result.connection_established:
        findings.append(SecurityFinding(
            finding_id="CONN-01",
            title="TLS Connection Establishment",
            severity="Critical",
            status="Fail",
            evidence=f"TCP connection to {tls_result.hostname}:{tls_result.port} ({tls_result.pinned_ip}) failed. Error: {tls_result.verification_error}",
            implication="Client was completely unable to reach or establish a socket connection with the target host. No TLS session could be negotiated.",
            recommendation="Verify that the target server is online, the hostname resolves to the correct IP, port 443 is open, and firewall rules permit inbound HTTPS traffic.",
            reference_standard="RFC 8446 Section 4",
            evidence_available=True
        ))
        assessment.overall_outcome = "FAILED"
        assessment.score_label = "Connection Failed"
        assessment.assessment_notes = "Scan aborted because the target server could not be reached over the network."
        _finalize_assessment(assessment, findings)
        return assessment

    # Rule 2: Certificate Trust Chain Verification
    if tls_result.verification_passed and tls_result.chain_verified_by_ca:
        findings.append(SecurityFinding(
            finding_id="TRUST-01",
            title="Trust Chain Verification",
            severity="Informational",
            status="Pass",
            evidence="TLS handshake successfully validated against the trusted system Certificate Authority (CA) store.",
            implication="The presented certificate was signed by a publicly trusted root CA or authorized intermediate CA, establishing cryptographic authenticity.",
            recommendation="Continue maintaining automated certificate renewals via trusted certificate authorities.",
            reference_standard="RFC 5280 Section 6.1",
            evidence_available=True
        ))
    else:
        err_msg = tls_result.verification_error or "Certificate validation failed."
        findings.append(SecurityFinding(
            finding_id="TRUST-01",
            title="Trust Chain Verification",
            severity="Critical",
            status="Fail",
            evidence=f"TLS certificate verification failed: {err_msg}",
            implication="Browsers and automated TLS clients will reject connections to this host with security warnings. Users may be exposed to Man-In-The-Middle (MITM) attacks.",
            recommendation="Replace self-signed or untrusted certificates with a valid certificate issued by an accredited public CA (e.g. Let's Encrypt), and verify intermediate CA bundles.",
            reference_standard="RFC 5280 Section 6.1",
            evidence_available=True
        ))

    # If certificate analysis failed or no certificate is present
    if not cert_result.parsed_successfully:
        findings.append(SecurityFinding(
            finding_id="CERT-01",
            title="X.509 Certificate Data Extraction",
            severity="High",
            status="Fail",
            evidence=f"Certificate could not be parsed: {cert_result.error or 'No certificate presented'}",
            implication="Essential certificate metadata (validity, public key, subject) could not be verified by the cryptographic parser.",
            recommendation="Ensure the server presents a valid ASN.1 DER-encoded X.509 certificate during the TLS handshake.",
            reference_standard="RFC 5280 Section 4",
            evidence_available=False
        ))
        assessment.overall_outcome = "INSECURE"
        _finalize_assessment(assessment, findings)
        return assessment

    # Rule 3: Hostname Verification (RFC 6125)
    if cert_result.hostname_matched:
        findings.append(SecurityFinding(
            finding_id="HOST-01",
            title="Hostname Verification",
            severity="Informational",
            status="Pass",
            evidence=f"Target hostname '{tls_result.hostname}' matches certificate identity ({cert_result.hostname_match_details}).",
            implication="The certificate was explicitly issued for this domain, preventing identity spoofing.",
            recommendation="Maintain correct domain names in the Subject Alternative Name extension during certificate issuance.",
            reference_standard="RFC 6125 Section 6.4",
            evidence_available=True
        ))
    else:
        san_display = ", ".join(cert_result.subject_alternative_names) if cert_result.subject_alternative_names else "None"
        findings.append(SecurityFinding(
            finding_id="HOST-01",
            title="Hostname Verification",
            severity="Critical",
            status="Fail",
            evidence=f"Target hostname '{tls_result.hostname}' did NOT match certificate identity. Presented SANs: [{san_display}], CN: '{cert_result.subject_common_name}'.",
            implication="Browsers will block access due to domain name mismatch (ERR_CERT_COMMON_NAME_INVALID). An attacker could serve an arbitrary valid cert from another site.",
            recommendation="Issue a certificate containing the exact hostname or a valid wildcard covering this domain in the Subject Alternative Name (SAN) extension.",
            reference_standard="RFC 6125 Section 6.4",
            evidence_available=True
        ))

    # Rule 4: Temporal Validity (Expiration & Not-Before)
    if cert_result.is_expired:
        findings.append(SecurityFinding(
            finding_id="TIME-01",
            title="Certificate Expiration Status",
            severity="Critical",
            status="Fail",
            evidence=f"Certificate expired on {cert_result.valid_to_iso} ({abs(cert_result.days_remaining)} days ago).",
            implication="The certificate is no longer cryptographically valid. Browsers will terminate HTTPS sessions with security warnings.",
            recommendation="Renew the certificate immediately and install the new certificate on the web server.",
            reference_standard="RFC 5280 Section 4.1.2.5",
            evidence_available=True
        ))
    elif cert_result.is_not_yet_valid:
        findings.append(SecurityFinding(
            finding_id="TIME-01",
            title="Certificate Temporal Validity",
            severity="High",
            status="Fail",
            evidence=f"Certificate is not valid until {cert_result.valid_from_iso}.",
            implication="The certificate validity period has not started yet. Clients with accurate system clocks will reject the connection.",
            recommendation="Verify server system time, NTP synchronization, and issuance timestamps.",
            reference_standard="RFC 5280 Section 4.1.2.5",
            evidence_available=True
        ))
    elif cert_result.days_remaining <= critical_days:
        findings.append(SecurityFinding(
            finding_id="TIME-01",
            title="Certificate Expiration Imminent",
            severity="High",
            status="Warning",
            evidence=f"Certificate expires in {cert_result.days_remaining} days ({cert_result.valid_to_iso}).",
            implication="Certificate expiration is imminent (less than 7 days remaining). Outages will occur if not renewed urgently.",
            recommendation="Trigger emergency certificate renewal immediately.",
            reference_standard="RFC 5280 Section 4.1.2.5",
            evidence_available=True
        ))
    elif cert_result.days_remaining <= warn_days:
        findings.append(SecurityFinding(
            finding_id="TIME-01",
            title="Certificate Expiring Soon",
            severity="Medium",
            status="Warning",
            evidence=f"Certificate expires in {cert_result.days_remaining} days ({cert_result.valid_to_iso}).",
            implication="Certificate expires within the standard 30-day renewal threshold.",
            recommendation="Ensure automated ACME / renewal processes are scheduled and operating correctly.",
            reference_standard="RFC 5280 Section 4.1.2.5",
            evidence_available=True
        ))
    else:
        findings.append(SecurityFinding(
            finding_id="TIME-01",
            title="Certificate Temporal Validity",
            severity="Informational",
            status="Pass",
            evidence=f"Certificate is currently valid (Valid from {cert_result.valid_from_iso} to {cert_result.valid_to_iso}; {cert_result.days_remaining} days remaining).",
            implication="Certificate operates within its authorized lifetime.",
            recommendation="No action required. Continue regular renewal monitoring.",
            reference_standard="RFC 5280 Section 4.1.2.5",
            evidence_available=True
        ))

    # Rule 5: Negotiated TLS Protocol Version
    version = tls_result.tls_version or "Unknown"
    if version == "TLSv1.3":
        findings.append(SecurityFinding(
            finding_id="PROTO-01",
            title="TLS Protocol Version",
            severity="Informational",
            status="Pass",
            evidence=f"Negotiated modern TLS protocol: {version} (RFC 8446).",
            implication="TLS 1.3 is the latest standard, offering improved security, mandatory Perfect Forward Secrecy (PFS), removed obsolete cryptographic primitives, and 1-RTT handshake latency.",
            recommendation="No action required. Modern protocol configuration verified.",
            reference_standard="RFC 8446",
            evidence_available=True
        ))
    elif version == "TLSv1.2":
        findings.append(SecurityFinding(
            finding_id="PROTO-01",
            title="TLS Protocol Version",
            severity="Low",
            status="Pass",
            evidence=f"Negotiated {version} (RFC 5246).",
            implication="TLS 1.2 is secure when configured with strong cipher suites, though TLS 1.3 provides superior security and speed.",
            recommendation="Enable TLS 1.3 on the web server or reverse proxy to benefit from modern zero-round-trip features and strict forward secrecy.",
            reference_standard="RFC 5246",
            evidence_available=True
        ))
    elif version in ("TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"):
        findings.append(SecurityFinding(
            finding_id="PROTO-01",
            title="Deprecated TLS/SSL Protocol Version",
            severity="Critical",
            status="Fail",
            evidence=f"Negotiated deprecated protocol: {version}.",
            implication="TLS 1.0 and 1.1 have been officially deprecated by the IETF (RFC 8996) due to structural weaknesses (BEAST, POODLE, lack of modern ciphers). Major browsers have removed support.",
            recommendation="Disable SSLv3, TLS 1.0, and TLS 1.1 immediately. Enforce TLS 1.2 and TLS 1.3.",
            reference_standard="RFC 8996",
            evidence_available=True
        ))
    else:
        findings.append(SecurityFinding(
            finding_id="PROTO-01",
            title="TLS Protocol Version",
            severity="Medium",
            status="Warning",
            evidence=f"Protocol negotiated: {version}.",
            implication="Unable to confirm if negotiated protocol version meets modern security standards.",
            recommendation="Inspect server TLS configuration to ensure TLS 1.2 and TLS 1.3 are enabled.",
            reference_standard="NIST SP 800-52r2",
            evidence_available=bool(tls_result.tls_version)
        ))

    # Rule 6: Cipher Suite & Authenticated Encryption (AEAD)
    cipher = tls_result.cipher_name or "Unknown"
    cipher_bits = tls_result.cipher_bits or 0
    if cipher:
        is_pfs = any(k in cipher for k in ["ECDHE", "DHE", "TLS_AES", "TLS_CHACHA"])
        is_aead = any(k in cipher for k in ["GCM", "POLY1305", "CCM"])
        is_weak = any(k in cipher for k in ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "anon"])
        
        if is_weak:
            findings.append(SecurityFinding(
                finding_id="CIPH-01",
                title="Cryptographic Cipher Suite Security",
                severity="Critical",
                status="Fail",
                evidence=f"Negotiated weak cipher suite: {cipher} ({cipher_bits}-bit).",
                implication="The cipher suite utilizes broken or vulnerable primitives that can be decrypted or exploited by adversaries.",
                recommendation="Disable weak cipher suites in server configuration. Restrict to AEAD ciphers with ECDHE key exchange.",
                reference_standard="NIST SP 800-52r2 Section 3.3.1",
                evidence_available=True
            ))
        elif is_pfs and is_aead and cipher_bits >= 128:
            findings.append(SecurityFinding(
                finding_id="CIPH-01",
                title="Cryptographic Cipher Suite Security",
                severity="Informational",
                status="Pass",
                evidence=f"Negotiated modern AEAD cipher suite: {cipher} ({cipher_bits}-bit).",
                implication="Traffic is protected with authenticated encryption (AEAD) ensuring simultaneous confidentiality and integrity.",
                recommendation="No action required. Modern cipher suite parameters in effect.",
                reference_standard="NIST SP 800-52r2 Section 3.3.1",
                evidence_available=True
            ))
        else:
            findings.append(SecurityFinding(
                finding_id="CIPH-01",
                title="Cryptographic Cipher Suite Security",
                severity="Medium",
                status="Warning",
                evidence=f"Negotiated cipher suite: {cipher} ({cipher_bits}-bit).",
                implication="The cipher suite may lack Authenticated Encryption (AEAD). Non-AEAD ciphers (e.g. CBC mode) are susceptible to padding oracle attacks.",
                recommendation="Update server configuration to prioritize ECDHE with AES-GCM or ChaCha20-Poly1305.",
                reference_standard="NIST SP 800-52r2 Section 3.3.1",
                evidence_available=True
            ))

    # Rule 7: Perfect Forward Secrecy (PFS) Key Exchange
    if tls_result.tls_version == "TLSv1.3":
        findings.append(SecurityFinding(
            finding_id="PFS-01",
            title="Perfect Forward Secrecy (PFS)",
            severity="Informational",
            status="Pass",
            evidence=f"TLS 1.3 negotiated with ephemeral Diffie-Hellman key share in session cipher {cipher}.",
            implication="Past encrypted sessions cannot be decrypted retrospectively even if the server private key is compromised in the future.",
            recommendation="No action required. Mandatory PFS enforced by TLS 1.3.",
            reference_standard="RFC 8446 Section 1.2",
            evidence_available=True
        ))
    elif any(k in cipher for k in ["ECDHE", "DHE"]):
        findings.append(SecurityFinding(
            finding_id="PFS-01",
            title="Perfect Forward Secrecy (PFS)",
            severity="Informational",
            status="Pass",
            evidence=f"Observed ephemeral key exchange primitive in cipher suite: {cipher}.",
            implication="Session keys are derived ephemerally via ECDHE/DHE, guaranteeing past traffic privacy against future private key leaks.",
            recommendation="No action required. Forward secrecy enabled.",
            reference_standard="NIST SP 800-52r2 Section 3.3",
            evidence_available=True
        ))
    elif tls_result.connection_established:
        findings.append(SecurityFinding(
            finding_id="PFS-01",
            title="Perfect Forward Secrecy (PFS)",
            severity="High",
            status="Fail",
            evidence=f"Negotiated cipher suite '{cipher}' relies on static key exchange without ephemeral Diffie-Hellman.",
            implication="Lacks Perfect Forward Secrecy. If the server's long-term RSA private key is ever compromised, an attacker can decrypt all past recorded communications.",
            recommendation="Reconfigure the TLS server to disable static RSA key exchange suites and enforce ECDHE.",
            reference_standard="NIST SP 800-52r2 Section 3.3",
            evidence_available=True
        ))
    else:
        findings.append(SecurityFinding(
            finding_id="PFS-01",
            title="Perfect Forward Secrecy (PFS)",
            severity="Informational",
            status="Not Evaluated",
            evidence="Connection was not established; PFS could not be evaluated.",
            implication="Unable to inspect key exchange parameters.",
            recommendation="Ensure the host is online and accessible over HTTPS.",
            reference_standard="RFC 8446",
            evidence_available=False
        ))

    # Rule 8: Public Key Cryptographic Strength
    key_algo = cert_result.public_key_algorithm
    key_size = cert_result.public_key_size or 0
    if key_algo == "RSA":
        if key_size >= 2048:
            findings.append(SecurityFinding(
                finding_id="KEY-01",
                title="Public Key Cryptographic Strength",
                severity="Informational",
                status="Pass",
                evidence=f"RSA public key length is {key_size} bits ({cert_result.public_key_details}).",
                implication="RSA key size complies with NIST SP 800-52r2 and CA/B Forum requirements (>= 2048 bits).",
                recommendation="For enhanced long-term resistance, consider migrating to 3072/4096-bit RSA or Elliptic Curve (ECDSA P-256/P-384).",
                reference_standard="NIST SP 800-52r2 Section 3.1",
                evidence_available=True
            ))
        else:
            findings.append(SecurityFinding(
                finding_id="KEY-01",
                title="Public Key Cryptographic Strength",
                severity="Critical",
                status="Fail",
                evidence=f"RSA public key length is only {key_size} bits (insufficient).",
                implication="RSA keys under 2048 bits are vulnerable to factorization attacks and are banned by all major browser root certificate programs.",
                recommendation="Immediately re-issue certificate using at least a 2048-bit (or 3072-bit) RSA key.",
                reference_standard="NIST SP 800-52r2 Section 3.1",
                evidence_available=True
            ))
    elif key_algo in ("EC", "Ed25519", "Ed448"):
        if key_size >= 256:
            findings.append(SecurityFinding(
                finding_id="KEY-01",
                title="Public Key Cryptographic Strength",
                severity="Informational",
                status="Pass",
                evidence=f"Elliptic Curve public key: {cert_result.public_key_details}.",
                implication="Elliptic Curve Cryptography provides equivalent high security with significantly smaller key sizes and faster mathematical handshakes.",
                recommendation="No action required. Modern cryptographic primitive.",
                reference_standard="NIST SP 800-52r2 Section 3.1",
                evidence_available=True
            ))
        else:
            findings.append(SecurityFinding(
                finding_id="KEY-01",
                title="Public Key Cryptographic Strength",
                severity="High",
                status="Fail",
                evidence=f"Elliptic Curve key size {key_size} bits is below the 256-bit standard.",
                implication="Sub-256 bit curves do not provide sufficient cryptographic strength against discrete log attacks.",
                recommendation="Use standard curves such as NIST P-256 (secp256r1) or P-384.",
                reference_standard="NIST SP 800-52r2 Section 3.1",
                evidence_available=True
            ))

    # Rule 9: Signature Algorithm Hash Function
    sig_algo = cert_result.signature_algorithm.lower()
    sig_hash = (cert_result.signature_hash_algorithm or "").lower()
    if "md5" in sig_algo or "md5" in sig_hash:
        findings.append(SecurityFinding(
            finding_id="SIG-01",
            title="Certificate Signature Algorithm",
            severity="Critical",
            status="Fail",
            evidence=f"Signature algorithm uses MD5: {cert_result.signature_algorithm}.",
            implication="MD5 has suffered catastrophic collision attacks. Attackers can forge valid certificates.",
            recommendation="Replace certificate immediately with one signed using SHA-256 or SHA-384.",
            reference_standard="RFC 5280 Section 4.1.1.2",
            evidence_available=True
        ))
    elif "sha1" in sig_algo or "sha1" in sig_hash:
        findings.append(SecurityFinding(
            finding_id="SIG-01",
            title="Certificate Signature Algorithm",
            severity="High",
            status="Fail",
            evidence=f"Signature algorithm uses deprecated SHA-1: {cert_result.signature_algorithm}.",
            implication="SHA-1 collision attacks make it obsolete. Untrusted by modern operating systems and web browsers.",
            recommendation="Replace certificate with SHA-256 (e.g. sha256WithRSAEncryption or ecdsa-with-SHA256).",
            reference_standard="RFC 5280 Section 4.1.1.2",
            evidence_available=True
        ))
    elif any(safe in sig_algo for safe in ["sha256", "sha384", "sha512", "ed25519"]):
        findings.append(SecurityFinding(
            finding_id="SIG-01",
            title="Certificate Signature Algorithm",
            severity="Informational",
            status="Pass",
            evidence=f"Modern secure signature algorithm: {cert_result.signature_algorithm}.",
            implication="Uses strong cryptographic collision-resistant hash functions.",
            recommendation="No action required.",
            reference_standard="RFC 5280 Section 4.1.1.2",
            evidence_available=True
        ))

    # Rule 10: Subject Alternative Name (SAN) Extension (RFC 6125)
    if cert_result.subject_alternative_names:
        findings.append(SecurityFinding(
            finding_id="SAN-01",
            title="Subject Alternative Name (SAN) Extension",
            severity="Informational",
            status="Pass",
            evidence=f"Certificate contains {len(cert_result.subject_alternative_names)} SAN entry/entries.",
            implication="Complies with RFC 6125. Modern browsers require SAN extensions and ignore Common Name for domain validation.",
            recommendation="No action required.",
            reference_standard="RFC 6125 Section 1.8",
            evidence_available=True
        ))
    else:
        findings.append(SecurityFinding(
            finding_id="SAN-01",
            title="Subject Alternative Name (SAN) Extension",
            severity="Medium",
            status="Warning",
            evidence="Certificate does not contain Subject Alternative Name (SAN) extension, relying solely on Common Name.",
            implication="Modern web browsers (Chrome, Firefox, Safari) strictly require SAN extensions and will reject certificates lacking SANs.",
            recommendation="Re-issue certificate with Subject Alternative Name extension containing the domain names.",
            reference_standard="RFC 6125 Section 1.8",
            evidence_available=True
        ))

    # Rule 11: HTTP Strict Transport Security (HSTS - RFC 6797)
    if tls_result.hsts_evaluated:
        if tls_result.hsts_present:
            if tls_result.hsts_max_age and tls_result.hsts_max_age >= 31536000:
                findings.append(SecurityFinding(
                    finding_id="HSTS-01",
                    title="HTTP Strict Transport Security (HSTS)",
                    severity="Informational",
                    status="Pass",
                    evidence=f"HSTS header present with strong duration: {tls_result.hsts_raw_header} (max-age={tls_result.hsts_max_age}s).",
                    implication="Enforces HTTPS connections at the browser level, mitigating SSL stripping and MITM attacks.",
                    recommendation="Maintain HSTS header on all HTTPS endpoints.",
                    reference_standard="RFC 6797 Section 6.1",
                    evidence_available=True
                ))
            else:
                findings.append(SecurityFinding(
                    finding_id="HSTS-01",
                    title="HTTP Strict Transport Security (HSTS)",
                    severity="Low",
                    status="Warning",
                    evidence=f"HSTS header present ({tls_result.hsts_raw_header}), but max-age ({tls_result.hsts_max_age}s) is below recommended 1 year (31,536,000s).",
                    implication="Short HSTS max-age durations reduce protection window against SSL stripping after user inactivity.",
                    recommendation="Increase HSTS max-age to at least 31536000 seconds (1 year) and consider includeSubDomains.",
                    reference_standard="RFC 6797 Section 6.1",
                    evidence_available=True
                ))
        else:
            findings.append(SecurityFinding(
                finding_id="HSTS-01",
                title="HTTP Strict Transport Security (HSTS)",
                severity="Medium",
                status="Warning",
                evidence="No Strict-Transport-Security HTTP response header detected on the endpoint.",
                implication="Clients making initial unencrypted HTTP requests may be vulnerable to SSL stripping attacks before redirecting to HTTPS.",
                recommendation="Configure web server to transmit 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                reference_standard="RFC 6797 Section 6.1",
                evidence_available=True
            ))
    else:
        findings.append(SecurityFinding(
            finding_id="HSTS-01",
            title="HTTP Strict Transport Security (HSTS)",
            severity="Informational",
            status="Not Evaluated",
            evidence=tls_result.hsts_eval_notes or "HTTP probe was not executed or socket connection failed.",
            implication="HSTS status could not be evaluated.",
            recommendation="Verify server is serving HTTP/HTTPS responses on target port.",
            reference_standard="RFC 6797 Section 6.1",
            evidence_available=False
        ))

    _finalize_assessment(assessment, findings)
    return assessment


def _finalize_assessment(
    assessment: SecurityAssessmentResult,
    findings: List[SecurityFinding]
) -> None:
    """Computes summary counts, deterministic educational score, and overall outcome."""
    assessment.findings = findings
    
    passes = sum(1 for f in findings if f.status in ("Pass", "PASS"))
    warnings = sum(1 for f in findings if f.status in ("Warning", "WARN"))
    failures = sum(1 for f in findings if f.status in ("Fail", "FAIL"))
    not_assessed = sum(1 for f in findings if f.status in ("Not Assessed", "NOT_EVALUATED", "Not Evaluated"))
    
    assessment.passed_count = passes
    assessment.warning_count = warnings
    assessment.failure_count = failures
    assessment.not_assessed_count = not_assessed

    # If connection was completely aborted
    if assessment.overall_outcome == "FAILED":
        assessment.educational_score = None
        assessment.score_label = "Scan Incomplete"
        return

    # Calculate deterministic educational score out of 100
    # Base: 100 points
    score = 100
    breakdown = []
    
    for f in findings:
        if f.status in ("Fail", "FAIL"):
            if f.severity == "Critical":
                score -= 35
                breakdown.append(f"-35 pts: Critical failure in {f.title}")
            elif f.severity == "High":
                score -= 25
                breakdown.append(f"-25 pts: High severity failure in {f.title}")
            elif f.severity == "Medium":
                score -= 15
                breakdown.append(f"-15 pts: Medium severity failure in {f.title}")
        elif f.status in ("Warning", "WARN"):
            if f.severity == "High":
                score -= 15
                breakdown.append(f"-15 pts: High warning in {f.title}")
            elif f.severity == "Medium":
                score -= 10
                breakdown.append(f"-10 pts: Warning in {f.title}")
            elif f.severity == "Low":
                score -= 5
                breakdown.append(f"-5 pts: Minor warning in {f.title}")

    # Enforce bounds
    score = max(0, min(100, score))
    assessment.educational_score = score
    assessment.score_breakdown = breakdown

    # Determine Overall Outcome
    if failures > 0 or score < 60:
        assessment.overall_outcome = "INSECURE"
        assessment.score_label = f"{score}/100 (Needs Remediation)"
    elif warnings > 0 or score < 85:
        assessment.overall_outcome = "WARNINGS"
        assessment.score_label = f"{score}/100 (Acceptable with Warnings)"
    else:
        assessment.overall_outcome = "SECURE"
        assessment.score_label = f"{score}/100 (Strong TLS Posture)"

    assessment.assessment_notes = (
        "Educational Score Notice: This numerical indicator is calculated deterministically from standard "
        "cryptographic rules (NIST SP 800-52r2, RFC 8446, RFC 5280, RFC 6797). It is intended for academic evaluation and "
        "benchmarking, not as a legal or commercial security guarantee."
    )
