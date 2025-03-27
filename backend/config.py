import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/security_scanner")

# ZAP API Configuration
ZAP_URL = os.getenv("ZAP_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "l73evs1395k61htfduf35f79ss")

# Flask Configuration
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

if not MONGO_URI:
    raise ValueError("MONGO_URI is not set in the .env file")

