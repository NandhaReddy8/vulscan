from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import time
import threading
import csv
from database import save_scan_request, save_report_request, get_scan_requests
from zap_scan import scan_target

# Load environment variables
FLASK_RUN_HOST = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
FLASK_RUN_PORT = int(os.getenv("FLASK_RUN_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"

RESULTS_DIR = "./zap_results"  # Directory where ZAP scan results are stored

# Initialize Flask App with WebSockets
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure Socket.IO with explicit settings
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,  # Increase ping timeout
    ping_interval=25  # Adjust ping interval
)

def is_duplicate_url(target_url):
    """Check if the given URL has already been submitted for scanning"""
    try:
        with open("scan_requests.csv", "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["url"] == target_url:
                    return True
    except FileNotFoundError:
        return False  # If CSV doesn't exist, no scans have been submitted yet
    except Exception as e:
        print(f"[ERROR] Failed to read scan_requests.csv: {e}")
    return False

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

    # **Step 1: Delete old JSON results if they exist**
    sanitized_url = target_url.replace("://", "_").replace("/", "_")
    json_filename = f"{RESULTS_DIR}/{sanitized_url}.json"

    if os.path.exists(json_filename):
        os.remove(json_filename)
        print(f"[*] Deleted old scan results: {json_filename}")

    # **Step 2: Run ZAP Scan in a separate thread**
    def run_scan():
        print(f"[*] Triggering scan for {target_url}...")
        try:
            scan_target(target_url, socketio)  # Pass socketio for real-time updates
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")
            socketio.emit('scan_completed', {'error': str(e), 'target_url': target_url})

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.daemon = True  # Make thread daemon so it exits when main thread exits
    scan_thread.start()

    return jsonify({"message": "Scan started!", "target_url": target_url})

# Socket.IO connection event handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('server_update', {'message': 'Connected to server successfully'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")

# Start the Flask Server
if __name__ == "__main__":
    socketio.run(app, debug=FLASK_DEBUG, host=FLASK_RUN_HOST, port=FLASK_RUN_PORT)
