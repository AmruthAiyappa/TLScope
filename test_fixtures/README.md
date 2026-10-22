# TLScope Test Fixtures & Local TLS Test Suite

This directory contains deterministic testing utilities and certificate factories for the TLScope test suite.

## Purpose

To reliably test:
1. **Valid Certificate Chains:** A generated test CA signs a valid leaf certificate.
2. **Expired Certificates:** Verifies that expired validity windows trigger `TIME-01` Critical failures.
3. **Hostname Mismatch:** Verifies that RFC 6125 SAN comparison catches mismatches between the target hostname and presented certificate identities (`HOST-01`).
4. **Untrusted Roots:** Verifies that self-signed or unanchored certificates trigger `TRUST-01` Critical verification failures.
5. **Weak Cryptography:** Verifies that 1024-bit RSA keys trigger `KEY-01` failures.

All cryptographic test fixtures are generated dynamically via `test_fixtures/cert_factory.py` using standard `cryptography.x509` structures, requiring no external network connectivity or external mock dependencies.
