import eventlet
eventlet.monkey_patch()
from OpenSSL import SSL
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import ssl
import time
import threading
import csv
import uuid
from database import save_scan_request, save_report_request, get_scan_requests
from zap_scan import scan_target, zap
from datetime import datetime, timedelta
from config import FLASK_DEBUG, FLASK_HOST, FLASK_PORT
from dojo_handler import DojoHandler

RESULTS_DIR = "./zap_results"  # Directory where ZAP scan results are stored
REPORTS_DIR = "./zap_reports"

# Initialize DojoHandler
dojo_handler = DojoHandler()

def check_weekly_scan_limit(target_url):
    """
    Check if URL has exceeded the weekly scan limit (2 scans per 7 days)
    Returns: (bool, str) - (is_limit_exceeded, error_message)
    """
    try:
        print(f"[*] Checking scan limit for URL: {target_url}")
        current_time = datetime.now()
        week_ago = current_time - timedelta(days=7)
        scan_count = 0
        
        # Get absolute path to scan_requests.csv
        current_dir = os.path.dirname(os.path.abspath(__file__))
        csv_file = os.path.join(current_dir, 'scan_requests.csv')
        
        print(f"[*] Looking for CSV file at: {csv_file}")

        if not os.path.exists(csv_file):
            print(f"[!] CSV file not found at: {csv_file}")
            # Create the file with correct headers
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['url', 'ip_address', 'timestamp'])
            return False, None

        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                
                # Convert headers to lowercase for case-insensitive comparison
                headers_lower = [h.lower() for h in headers] if headers else []
                required_headers = {'url', 'ip_address', 'timestamp'}
                
                if not headers or not required_headers.issubset(set(headers_lower)):
                    print(f"[!] Invalid or missing headers. Found: {headers}")
                    print("[*] Creating new file with correct headers")
                    
                    # Backup existing file
                    backup_file = f"{csv_file}.backup"
                    if os.path.exists(csv_file):
                        os.rename(csv_file, backup_file)
                    
                    # Create new file with correct headers
                    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(['url', 'ip_address', 'timestamp'])
                    return False, None
                
                print(f"[*] Reading scan history...")
                recent_scans = []
                
                # Create a mapping of header names
                header_map = {h.lower(): h for h in headers}
                
                for row in reader:
                    # Use header mapping to get values
                    url_value = row[header_map.get('url', 'URL')]
                    timestamp_value = row[header_map.get('timestamp', 'Time Stamp')]
                    
                    # Skip if URL doesn't match
                    if url_value.strip() != target_url.strip():
                        continue
                        
                    try:
                        scan_time = datetime.strptime(timestamp_value, '%d-%m-%Y %H:%M:%S')
                        if scan_time > week_ago:
                            scan_count += 1
                            recent_scans.append(scan_time)
                            print(f"[+] Found recent scan from: {scan_time}")
                            
                            if scan_count >= 2:
                                earliest_scan = min(recent_scans)
                                days_until_reset = (earliest_scan + timedelta(days=7) - current_time).days + 1
                                error_msg = f"Weekly scan limit reached for this URL. Please try again after {days_until_reset} days."
                                print(f"[!] {error_msg}")
                                return True, error_msg
                                
                    except ValueError as e:
                        print(f"[ERROR] Invalid timestamp format in row: {timestamp_value}")
                        continue
                
                print(f"[*] Found {scan_count} scans in the last 7 days")
                return False, None
                
        except csv.Error as e:
            print(f"[ERROR] CSV file error: {str(e)}")
            return False, f"Error reading scan history: {str(e)}"
            
    except Exception as e:
        error_msg = f"Failed to check weekly scan limit: {str(e)}"
        print(f"[ERROR] {error_msg}")
        return False, error_msg

# Initialize Flask App with WebSockets
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure Socket.IO with explicit settings
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='eventlet',
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

def get_client_ip(request):
    """Get the real client IP address when behind Nginx"""
    # Try to get IP from X-Forwarded-For header first
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs - first one is the client
        return forwarded_for.split(',')[0].strip()
    
    # Try X-Real-IP header next (commonly set by Nginx)
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
        
    # Fallback to remote address
    return request.remote_addr

@app.route("/api/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        target_url = data.get("url")
        session_id = data.get("session_id")

        print(f"[*] Received scan request for URL: {target_url}")

        if not target_url:
            return jsonify({"error": "No URL provided"}), 400

        if not session_id:
            return jsonify({"error": "No session_id provided"}), 400

        # Check weekly scan limit
        print(f"[*] Checking scan limit...")
        is_limited, limit_message = check_weekly_scan_limit(target_url)
        
        if is_limited:
            print(f"[!] Scan limit reached: {limit_message}")
            return jsonify({"error": limit_message}), 429

        # Get the user's IP address
        user_ip = get_client_ip(request)

        # Format the timestamp in dd-mm-yyyy HH:MM:SS format
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        # Save scan request to CSV
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            csv_file = os.path.join(current_dir, 'scan_requests.csv')

            # Define the correct headers and data
            headers = ['url', 'ip_address', 'timestamp']
            csv_data = {
                'url': target_url,
                'ip_address': user_ip,
                'timestamp': timestamp
            }

            # Create file with headers if it doesn't exist
            file_exists = os.path.exists(csv_file)
            with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(csv_data)

            print(f"[+] Scan request saved to CSV: {csv_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save scan request to CSV: {str(e)}")

        # Add URL to running scans
        running_scans[target_url] = datetime.now()

        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = session_id

        # Run ZAP Scan in a separate thread
        def run_scan():
            nonlocal scan_id, target_url
            print(f"[*] Triggering scan for {target_url}...")
            try:
                scan_target(target_url, socketio, scan_id, active_scans)
            except Exception as e:
                print(f"[ERROR] Scan failed: {e}")
                session_id = active_scans.get(scan_id)
                if session_id:
                    socketio.emit('scan_completed', {'error': str(e), 'target_url': target_url}, room=session_id)
            finally:
                running_scans.pop(target_url, None)

        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({"message": "Scan started!", "scan_id": scan_id, "target_url": target_url})

    except Exception as e:
        error_msg = f"Scan request failed: {str(e)}"
        print(f"[ERROR] {error_msg}")
        return jsonify({"error": error_msg}), 500

@app.route("/api/report-request", methods=["POST"])
def handle_report_request():
    try:
        data = request.get_json()
        print(f"[*] Received report request for target: {data.get('targetUrl', 'Unknown')}")

        # Validate required fields
        required_fields = ['name', 'email', 'targetUrl']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        target_url = data['targetUrl']
        
        # Save report request to CSV
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            csv_file = os.path.join(current_dir, 'report_requests.csv')
            
            headers = ['Name', 'Email', 'Phone', 'Target URL', 'Timestamp']
            csv_data = {
                'Name': data['name'],
                'Email': data['email'],
                'Phone': data.get('phone', ''),
                'Target URL': target_url,
                'Timestamp': datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            }
            
            file_exists = os.path.exists(csv_file)
            with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(csv_data)
            
            print(f"[+] Report request saved to CSV: {csv_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save report request to CSV: {str(e)}")
        
        # Look for HTML report
        clean_url = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        report_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'zap_reports'
        )
        
        # Find the most recent HTML report for this URL
        html_files = [f for f in os.listdir(report_dir) 
                     if clean_url in f and f.endswith('.html')]
        
        if not html_files:
            return jsonify({
                "error": "Scan report not found. Please ensure scan is completed."
            }), 404
            
        # Get the most recent report
        html_path = os.path.join(report_dir, html_files[-1])
        
        try:
            return send_file(
                html_path,
                mimetype='text/html',
                as_attachment=False  # This will open in browser
            )
        except Exception as e:
            print(f"[ERROR] Failed to send file: {str(e)}")
            return jsonify({"error": "Failed to send report file"}), 500

    except Exception as e:
        print(f"[ERROR] Report request failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/stop-scan", methods=["POST", "OPTIONS"])
def stop_scan():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response

    try:
        data = request.get_json()
        session_id = data.get("session_id")
        target_url = data.get("url")

        if not session_id:
            return jsonify({"error": "No session_id provided"}), 400

        # Find the scan_id for this session
        scan_id = next((sid for sid, sess in active_scans.items() 
                       if sess == session_id), None)

        if not scan_id:
            return jsonify({"error": "No active scan found"}), 404

        print(f"[*] Stopping scan for {target_url}")

        # Stop ZAP scans
        zap.spider.stop_all_scans()
        zap.ascan.stop_all_scans()
        zap.pscan.disable_all_scanners()

        # Remove from tracking immediately
        active_scans.pop(scan_id, None)
        running_scans.pop(target_url, None)

        # Clean up context
        context_name = f"context_{scan_id}"
        try:
            zap.context.remove_context(context_name)
            print(f"[+] Removed context {context_name}")
        except Exception as e:
            print(f"[WARNING] Error removing context: {str(e)}")

        # Notify client immediately
        socketio.emit('scan_stopped', {
            'scan_id': scan_id,
            'message': 'Scan stopped by user',
            'status': 'stopped'
        }, room=session_id)

        print(f"[+] Successfully stopped scan for {target_url}")
        return jsonify({"message": "Scan stopped successfully"}), 200

    except Exception as e:
        print(f"[ERROR] Stop scan request failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Add this route to serve HTML reports
@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory('zap_reports', filename)

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
    socketio.run(app, debug=FLASK_DEBUG, host=FLASK_HOST, port=FLASK_PORT)