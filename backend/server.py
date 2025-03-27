from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO
import os
import time
import threading
import csv
from database import save_scan_request, save_report_request, get_scan_requests
from zap_scan import scan_target  # Import scan function

# Load environment variables
FLASK_RUN_HOST = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
FLASK_RUN_PORT = int(os.getenv("FLASK_RUN_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

# Initialize Flask App with WebSockets
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # Enables real-time communication

# Check if URL is already scanned
def is_duplicate_url(target_url):
    """Check if the given URL has already been submitted for scanning"""
    try:
        with open("scan_requests.csv", "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["url"] == target_url:
                    return True
    except FileNotFoundError:
        return False  # If the CSV doesn't exist, no scans have been submitted yet
    except Exception as e:
        print(f"[ERROR] Failed to read scan_requests.csv: {e}")
    return False

# API Endpoint: Handle Scan Request & Trigger Scan Immediately
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_url = data.get("url")

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    # Check for duplicate URL
    if is_duplicate_url(target_url):
        return jsonify({"error": "This URL has already been submitted for scanning!"}), 400

    timestamp = time.time()
    save_scan_request(target_url, timestamp)

    # Run ZAP Scan in a separate thread (to avoid blocking)
    def run_scan():
        print(f"[*] Triggering scan for {target_url}...")
        scan_target(target_url, socketio)  # Pass socketio for real-time updates

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

    return jsonify({"message": "Scan started!", "target_url": target_url})

# Start the Flask Server
if __name__ == "__main__":
    socketio.run(app, debug=FLASK_DEBUG, host=FLASK_RUN_HOST, port=FLASK_RUN_PORT)
