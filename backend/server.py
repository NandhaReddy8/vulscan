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
from db_handler import DatabaseHandler

db = DatabaseHandler()



def check_weekly_scan_limit(target_url):
    """
    Check if URL has exceeded the weekly scan limit (2 scans per 7 days)
    Returns: (bool, str) - (is_limit_exceeded, error_message)
    """
    try:
        print(f"[*] Checking scan limit for URL: {target_url}")
        current_time = datetime.now()
        week_ago = current_time - timedelta(days=7)
        
        # Get scan count from database
        conn = db.get_connection()
        try:
            with conn.cursor() as cur:
                # Get recent scans for the URL in the last 7 days
                cur.execute("""
                    SELECT timestamp 
                    FROM scan_requests 
                    WHERE url = %s 
                    AND timestamp > %s 
                    ORDER BY timestamp DESC
                    """, (target_url, week_ago))
                
                recent_scans = [row[0] for row in cur.fetchall()]
                scan_count = len(recent_scans)
                
                print(f"[*] Found {scan_count} scans in the last 7 days")
                
                if scan_count >= 2:
                    earliest_scan = min(recent_scans)
                    days_until_reset = (earliest_scan + timedelta(days=7) - current_time).days + 1
                    error_msg = f"Weekly scan limit reached for this URL. Please try again after {days_until_reset} days."
                    print(f"[!] {error_msg}")
                    return True, error_msg
                
                return False, None
                
        except Exception as e:
            print(f"[ERROR] Database query failed: {str(e)}")
            raise
        finally:
            db.put_connection(conn)
            
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
        
        if (is_limited):
            print(f"[!] Scan limit reached: {limit_message}")
            return jsonify({"error": limit_message}), 429

        # Get the user's IP address and timestamp
        user_ip = get_client_ip(request)
        timestamp = datetime.now()

        # Save scan request to database instead of CSV
        try:
            save_scan_request(target_url, user_ip, timestamp)
            print(f"[+] Scan request saved to database")
        except Exception as e:
            print(f"[ERROR] Failed to save scan request: {str(e)}")

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

        target_url = data['targetUrl']
        
        # Normalize target URL for matching
        clean_url = target_url
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = f"https://{clean_url}"

        print(f"[DEBUG] Normalized URL: {clean_url}")
        
        # Save report request
        try:
            timestamp = datetime.now()
            save_report_request(
                data['name'],
                data['email'],
                data.get('phone', ''),
                clean_url,
                timestamp
            )
        except Exception as e:
            print(f"[ERROR] Failed to save report request: {str(e)}")

        # Get report from database with better URL matching
        try:
            conn = db.get_connection()
            try:
                with conn.cursor() as cur:
                    # More comprehensive URL patterns
                    url_patterns = [
                        f"%{clean_url}%",  # Full URL
                        f"%{target_url}%",  # Original input
                        f"%{target_url.replace('http://', '').replace('https://', '')}%",  # Without protocol
                        f"%{target_url.strip('/')}%",  # Without trailing slash
                        f"%{clean_url.replace('http://', '').replace('https://', '')}%"  # Normalized without protocol
                    ]
                    
                    print(f"[DEBUG] Trying URL patterns: {url_patterns}")
                    
                    # Try each pattern
                    for pattern in url_patterns:
                        cur.execute("""
                            SELECT content, target_url 
                            FROM zap_reports 
                            WHERE target_url LIKE %s 
                            AND report_type = 'html'
                            ORDER BY timestamp DESC 
                            LIMIT 1
                            """, (pattern,))
                        result = cur.fetchone()
                        
                        if result:
                            print(f"[+] Retrieved report from database using pattern: {pattern}")
                            print(f"[DEBUG] Matched with stored URL: {result[1]}")
                            return result[0], 200, {'Content-Type': 'text/html; charset=utf-8'}

                    print("[!] No matching report found in database")
                    return jsonify({
                        "error": "Scan report not found. Please ensure scan is completed."
                    }), 404
            finally:
                db.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to retrieve report from database: {str(e)}")
            return jsonify({"error": f"Failed to retrieve report: {str(e)}"}), 500

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

# Update the socket binding logic to handle IP addresses properly
if __name__ == "__main__":
    try:
        # Convert FLASK_HOST to string and handle IP validation
        host = str(FLASK_HOST)
        if host == "0.0.0.0":
            print(f"[INFO] Server will be accessible from all network interfaces")
        elif not all(c.isdigit() or c == '.' for c in host.split('.')):
            print(f"[WARNING] Invalid IP address format: {host}, falling back to localhost")
            host = "127.0.0.1"
            
        print(f"[INFO] Starting server on {host}:{FLASK_PORT}")
        socketio.run(
            app,
            host=host,
            port=int(FLASK_PORT),
            debug=FLASK_DEBUG,
            use_reloader=FLASK_DEBUG
        )
    except Exception as e:
        print(f"[ERROR] Failed to start server: {str(e)}")
        raise