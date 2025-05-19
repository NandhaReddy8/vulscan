import os
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

# Flask Configuration
FLASK_HOST = os.getenv("FLASK_HOST", "192.168.1.10")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

# Security Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# CORS Configuration
# Read CORS origins from environment variable, split by comma
# Format in .env: CORS_ORIGINS=http://site1.com,http://site2.com,http://site3.com
DEFAULT_CORS_ORIGINS = [
    "http://192.168.1.19:5173",  # Marketing frontend
    "http://192.168.1.19:5174",  # Main frontend
    "http://localhost:5173",      # Local marketing frontend
    "http://localhost:5174",      # Local main frontend
    "http://127.0.0.1:5173",      # Local marketing frontend alternative
    "http://127.0.0.1:5174",      # Local main frontend alternative
]

# Get CORS origins from environment variable, fallback to defaults if not set
CORS_ORIGINS_STR = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = CORS_ORIGINS_STR.split(",") if CORS_ORIGINS_STR else DEFAULT_CORS_ORIGINS

# Clean up any empty strings or whitespace from the origins list
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS if origin.strip()]

# Print CORS configuration on startup
print(f"[INFO] CORS enabled for origins: {CORS_ORIGINS}")

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
RATELIMIT_DEFAULT = "200 per day"
RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "memory://")
RATELIMIT_STRATEGY = "fixed-window"

# Ensure required environment variables are set in production
if not FLASK_DEBUG:
    required_vars = ["JWT_SECRET_KEY"]  # Removed CORS_ORIGINS since it's optional now
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

