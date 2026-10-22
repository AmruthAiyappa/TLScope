"""
Configuration settings for TLScope application.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("TLSCOPE_SECRET_KEY", "tlscope-insecure-dev-key-change-in-prod-2026")
    DATABASE_PATH = os.environ.get("TLSCOPE_DB_PATH", str(BASE_DIR / "database" / "tlscope.db"))
    
    # Network and Scan Settings
    DEFAULT_PORT = 443
    ALLOWED_PORTS = [443, 8443, 4433, 9443]  # Standard TLS service ports
    SOCKET_CONNECT_TIMEOUT = float(os.environ.get("TLSCOPE_CONNECT_TIMEOUT", "6.0"))
    SOCKET_READ_TIMEOUT = float(os.environ.get("TLSCOPE_READ_TIMEOUT", "6.0"))
    
    # SSRF Protection
    ALLOW_PRIVATE_IPS = os.environ.get("TLSCOPE_ALLOW_PRIVATE_IPS", "False").lower() in ("true", "1", "yes")
    
    # Security Assessment Thresholds
    CERT_EXPIRY_WARN_DAYS = 30
    CERT_EXPIRY_CRITICAL_DAYS = 7
    MIN_RSA_KEY_SIZE = 2048
    RECOMMENDED_RSA_KEY_SIZE = 3072
    MIN_EC_KEY_SIZE = 256
    
    # History settings
    MAX_HISTORY_ENTRIES = 50

class TestConfig(Config):
    """Testing configuration with local test database."""
    TESTING = True
    DATABASE_PATH = str(BASE_DIR / "database" / "test_tlscope.db")
    ALLOW_PRIVATE_IPS = True  # Allows testing against local test fixtures (127.0.0.1)
    SOCKET_CONNECT_TIMEOUT = 2.0
    SOCKET_READ_TIMEOUT = 2.0
