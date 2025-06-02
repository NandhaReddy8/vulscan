import os
from dotenv import load_dotenv
from datetime import timedelta
import ipaddress

# Load environment variables from .env file
load_dotenv()

# Flask Configuration
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

# CAPTCHA Configuration
CAPTCHA_VERIFY_URL = os.getenv("CAPTCHA_VERIFY_URL", "http://127.0.0.1:5000/api/cap/verify")
CAPTCHA_DIFFICULTY = int(os.getenv("CAPTCHA_DIFFICULTY", "4"))
CAPTCHA_EXPIRY = int(os.getenv("CAPTCHA_EXPIRY", "300"))
CAPTCHA_LENGTH = int(os.getenv("CAPTCHA_LENGTH", "32"))

# Security Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# CORS Configuration
# Scanner routes - allow all origins by default
SCANNER_CORS_ORIGINS = os.getenv("SCANNER_CORS_ORIGINS", "*")

# Marketing routes - restricted origins
DEFAULT_MARKETING_CORS_ORIGINS = [
    "http://192.168.1.23:5173",  # Marketing frontend
    "http://192.168.1.23:5174",  # Main frontend
    "http://localhost:5173",      # Local marketing frontend
    "http://localhost:5174",      # Local main frontend
    "http://127.0.0.1:5173",      # Local marketing frontend alternative
    "http://127.0.0.1:5174",      # Local main frontend alternative
    "http://localhost:3000",      # Common development port
    "http://127.0.0.1:3000",      # Common development port alternative
    "http://localhost:8080",      # Common development port
    "http://127.0.0.1:8080"       # Common development port alternative
]

# Get marketing CORS origins from environment variable, fallback to defaults if not set
MARKETING_CORS_ORIGINS_STR = os.getenv("MARKETING_CORS_ORIGINS", "")
MARKETING_CORS_ORIGINS = MARKETING_CORS_ORIGINS_STR.split(",") if MARKETING_CORS_ORIGINS_STR else DEFAULT_MARKETING_CORS_ORIGINS

# Clean up any empty strings or whitespace from the origins list
MARKETING_CORS_ORIGINS = [origin.strip() for origin in MARKETING_CORS_ORIGINS if origin.strip()]

# IP Range Restrictions for Production
def parse_ip_ranges(ip_ranges_str):
    """Parse IP ranges from comma-separated string into list of ipaddress.IPv4Network objects"""
    if not ip_ranges_str:
        return []
    try:
        return [ipaddress.IPv4Network(ip_range.strip()) for ip_range in ip_ranges_str.split(",") if ip_range.strip()]
    except ValueError as e:
        print(f"[WARNING] Invalid IP range format: {str(e)}")
        return []

ALLOWED_IP_RANGES_STR = os.getenv("ALLOWED_IP_RANGES", "")
ALLOWED_IP_RANGES = parse_ip_ranges(ALLOWED_IP_RANGES_STR)

def is_ip_allowed(ip_str):
    """Check if an IP address is within the allowed ranges"""
    if FLASK_DEBUG:
        return True  # Allow all IPs in debug mode
    if not ALLOWED_IP_RANGES:
        return True  # Allow all IPs if no ranges specified
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in network for network in ALLOWED_IP_RANGES)
    except ValueError:
        return False

# Print configuration on startup
print(f"[INFO] Scanner CORS enabled for: {SCANNER_CORS_ORIGINS}")
print(f"[INFO] Marketing CORS enabled for origins: {MARKETING_CORS_ORIGINS}")
if not FLASK_DEBUG and ALLOWED_IP_RANGES:
    print(f"[INFO] IP range restrictions enabled for: {[str(net) for net in ALLOWED_IP_RANGES]}")

# Database Configuration
DB_NAME = os.getenv("DB_NAME", "vulscan")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")

# ZAP API Configuration
ZAP_URL = os.getenv("ZAP_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "3ek27hdj10tooh0defcrknlm8o")

# Rate Limiting
RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day")
RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "memory://")
RATELIMIT_STRATEGY = os.getenv("RATELIMIT_STRATEGY", "fixed-window")

# Ensure required environment variables are set in production
if not FLASK_DEBUG:
    required_vars = ["JWT_SECRET_KEY"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

