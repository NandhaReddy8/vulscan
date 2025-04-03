from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import time
import threading
import csv
import uuid
from database import save_scan_request, save_report_request, get_scan_requests
from zap_scan import scan_target
from datetime import datetime, timedelta
import eventlet
eventlet.monkey_patch()  # Add this at the top


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

# Maintain a mapping of scan_id -> session_id
active_scans = {}
SCAN_COOLDOWN = timedelta(minutes=5)  # Adjust cooldown period as needed
running_scans = {}  # Track currently running scans with their start times

def is_duplicate_url(target_url):
    """Check if the URL is currently being scanned or was scanned very recently"""
    current_time = datetime.now()
    
    # Clean up old entries
    expired_urls = [url for url, start_time in running_scans.items() 
                   if current_time - start_time > SCAN_COOLDOWN]
    for url in expired_urls:
        running_scans.pop(url)
    
    # Check if URL is currently being scanned
    if target_url in running_scans:
        time_elapsed = current_time - running_scans[target_url]
        if time_elapsed < SCAN_COOLDOWN:
            return True
    return False

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_url = data.get("url")
    session_id = data.get("session_id")  # Get session_id from the request

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    if not session_id:
        return jsonify({"error": "No session_id provided"}), 400

    # Check for duplicate URL
    if is_duplicate_url(target_url):
        return jsonify({"error": "This URL is currently being scanned. Please wait a few minutes before trying again."}), 400

    # Add URL to running scans
    running_scans[target_url] = datetime.now()

    timestamp = time.time()
    scan_id = str(uuid.uuid4())  # Generate a unique scan ID
    save_scan_request(target_url, timestamp)

    # Map scan_id to session_id
    active_scans[scan_id] = session_id

    # Delete old JSON results if they exist
    sanitized_url = target_url.replace("://", "_").replace("/", "_")
    json_filename = f"{RESULTS_DIR}/{sanitized_url}.json"

    if os.path.exists(json_filename):
        os.remove(json_filename)
        print(f"[*] Deleted old scan results: {json_filename}")

    # Run ZAP Scan in a separate thread
    def run_scan():
        nonlocal scan_id, target_url  # Use nonlocal instead of global
        print(f"[*] Triggering scan for {target_url}...")
        try:
            scan_target(target_url, socketio, scan_id, active_scans)  # Pass active_scans as parameter
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")
            session_id = active_scans.get(scan_id)
            if session_id:
                socketio.emit('scan_completed', {'error': str(e), 'target_url': target_url}, room=session_id)
        finally:
            # Remove URL from running scans when complete
            running_scans.pop(target_url, None)

    scan_thread = threading.Thread(target=run_scan)
    scan_thread.daemon = True  # Make thread daemon so it exits when main thread exits
    scan_thread.start()

    return jsonify({"message": "Scan started!", "scan_id": scan_id, "target_url": target_url})

@app.route("/api/report-request", methods=["POST"])
def handle_report_request():
    try:
        data = request.get_json()
        print(f"[*] Received report request for target: {data.get('targetUrl', 'Unknown')}")
        
        # Validate required fields
        required_fields = ['name', 'email', 'company', 'companySize', 'targetUrl']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            print(f"[ERROR] Missing required fields: {missing_fields}")
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        # Format data for CSV
        csv_data = {
            'name': data['name'],
            'email': data['email'],
            'organization': data['company'],
            'size': data['companySize'],
            'phone': data.get('phone', 'Not provided'),
            'target_url': data['targetUrl'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Get the absolute path for the CSV file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        csv_file = os.path.join(current_dir, 'report_requests.csv')
        
        try:
            # Ensure the file exists or create with headers
            if not os.path.exists(csv_file):
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=csv_data.keys())
                    writer.writeheader()

            # Append the new data
            with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_data.keys())
                writer.writerow(csv_data)
            print(f"[+] Successfully saved request to CSV: {csv_file}")
        except Exception as e:
            print(f"[ERROR] Failed to write to CSV: {str(e)}")
            return jsonify({"error": "Failed to save request data"}), 500

        # Get ZAP report file
        safe_filename = data['targetUrl'].replace("://", "_").replace("/", "_").replace(":", "_")
        report_path = os.path.join(current_dir, RESULTS_DIR, f"{safe_filename}.json")
        
        if not os.path.exists(report_path):
            print(f"[ERROR] Report not found at: {report_path}")
            return jsonify({"error": "Scan report not found. Please ensure scan is completed."}), 404

        print(f"[+] Sending report file: {report_path}")
        try:
            return send_file(
                report_path,
                mimetype='application/json',
                as_attachment=True,
                download_name=f"security_report_{safe_filename}.json"
            )
        except Exception as e:
            print(f"[ERROR] Failed to send file: {str(e)}")
            return jsonify({"error": "Failed to send report file"}), 500

    except Exception as e:
        print(f"[ERROR] Report request failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Socket.IO connection event handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('server_update', {'message': 'Connected to server successfully'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Remove any scans associated with this session
    disconnected_scans = [scan_id for scan_id, session_id in active_scans.items() 
                         if session_id == request.sid]
    for scan_id in disconnected_scans:
        active_scans.pop(scan_id, None)

# Start the Flask Server
if __name__ == "__main__":
    socketio.run(app, debug=FLASK_DEBUG, host=FLASK_RUN_HOST, port=FLASK_RUN_PORT, server='eventlet')
