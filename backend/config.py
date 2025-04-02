import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ZAP API Configuration
ZAP_URL = os.getenv("ZAP_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "3ek27hdj10tooh0defcrknlm8o")

# Flask Configuration
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

