"""
Certificate Factory for Controlled TLS Testing and Test Fixtures.

Generates real cryptographic test certificates (X.509 DER and PEM bytes)
without requiring external network access or OpenSSL command line utilities:
- Root CA
- Valid Leaf Certificate
- Expired Leaf Certificate
- Hostname Mismatch Leaf Certificate
- Untrusted Self-Signed Certificate
- Weak Key (1024-bit RSA) Certificate
"""

import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_test_ca():
    """Generates a self-signed Root CA private key and certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLScope Test Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TLScope Root CA"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def generate_leaf_cert(
    ca_key,
    ca_cert,
    common_name="test.local",
    san_dns_names=None,
    expired=False,
    not_yet_valid=False,
    key_size=2048,
    hash_algorithm=hashes.SHA256()
):
    """Generates a leaf certificate signed by the specified CA."""
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLScope Test Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        valid_from = now - datetime.timedelta(days=60)
        valid_to = now - datetime.timedelta(days=10)
    elif not_yet_valid:
        valid_from = now + datetime.timedelta(days=10)
        valid_to = now + datetime.timedelta(days=60)
    else:
        valid_from = now - datetime.timedelta(days=1)
        valid_to = now + datetime.timedelta(days=90)
        
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
    )
    
    if san_dns_names is not None:
        names = [x509.DNSName(name) for name in san_dns_names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )
        
    leaf_cert = builder.sign(ca_key, hash_algorithm)
    return leaf_key, leaf_cert


def generate_self_signed_cert(common_name="untrusted.local", san_dns_names=None):
    """Generates a standalone untrusted self-signed certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san_dns_names:
        names = [x509.DNSName(name) for name in san_dns_names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return key, cert
