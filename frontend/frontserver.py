from flask import Flask, render_template
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

FLASK_RUN_HOST = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
FLASK_RUN_PORT = int(os.getenv("FLASK_RUN_PORT", 5001))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

# Initialize Flask App
app = Flask(__name__, static_folder="static", template_folder="templates")

# Serve the main frontend (index.html)
@app.route("/")
def home():
    return render_template("index.html")

# Start the Flask Frontend Server
if __name__ == "__main__":
    app.run(debug=FLASK_DEBUG, host=FLASK_RUN_HOST, port=FLASK_RUN_PORT)
