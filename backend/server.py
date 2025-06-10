import eventlet
eventlet.monkey_patch()
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import threading
import uuid
import secrets
import requests

from zap_scan import scan_target, zap, sanitize_url
from datetime import datetime, timedelta
from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    JWT_SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES, JWT_REFRESH_TOKEN_EXPIRES,
    SCANNER_CORS_ORIGINS, MARKETING_CORS_ORIGINS, is_ip_allowed,
    RATELIMIT_DEFAULT, RATELIMIT_STORAGE_URL, RATELIMIT_STRATEGY,
    RECAPTCHA_SECRET_KEY
)
from db_handler import DatabaseHandler
from psycopg2.extras import DictCursor
import logging
import json
from networkscan import start_network_scan, get_scan_status
import re

# Configure logging
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = JWT_SECRET_KEY

# Initialize database
db = DatabaseHandler()

# Global dictionaries to track scans
active_scans = {}
running_scans = {}

def check_weekly_scan_limit(target_url):
    """
    Check if URL has exceeded the weekly scan limit (2 scans per 7 days)
    Only applies to application scans (scan_requests table is application-scanner-only)
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

# Define CORS policies for different routes
scanner_cors = {
    "origins": "*",  # Allow all origins for scanner routes
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization", "X-Requester-IP", "X-Internal-Verify"],
    "supports_credentials": True,
    "expose_headers": ["Content-Type", "Authorization"],
    "max_age": 3600
}

marketing_cors = {
    "origins": MARKETING_CORS_ORIGINS,  # Restrict to specific origins for marketing routes
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization", "X-Requester-IP", "X-Internal-Verify"],
    "supports_credentials": True,
    "expose_headers": ["Content-Type", "Authorization", "Set-Cookie"],
    "max_age": 3600,
    "send_wildcard": False,
    "vary_header": True
}

# Apply CORS to specific routes
CORS(app, resources={
    # Scanner routes - allow all origins
    r"/api/scan": scanner_cors,
    r"/api/stop-scan": scanner_cors,
    r"/api/network/*": scanner_cors,
    r"/socket.io/*": scanner_cors,
    r"/api/network/start-scan": scanner_cors,
    r"/api/scan-report-summary": scanner_cors,
    r"/api/report-request": scanner_cors,
    
    # Marketing routes - restricted origins
    r"/api/auth/*": marketing_cors,
    # r"/api/scan-report-summary": marketing_cors,
    # r"/api/report-request": marketing_cors
}, supports_credentials=True)  # Enable credentials support globally

# Configure JWT
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = JWT_ACCESS_TOKEN_EXPIRES
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = JWT_REFRESH_TOKEN_EXPIRES
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Disable CSRF protection since we're using HTTP-only cookies
app.config["JWT_COOKIE_SECURE"] = not FLASK_DEBUG
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config["JWT_ERROR_MESSAGE_KEY"] = "error"  # Use consistent error message key
jwt = JWTManager(app)

# Add JWT error handlers
@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    print(f"[DEBUG] Invalid token error: {error_string}")
    return jsonify({"error": "Invalid token"}), 422

@jwt.unauthorized_loader
def unauthorized_callback(error_string):
    print(f"[DEBUG] Missing token error: {error_string}")
    return jsonify({"error": "Missing token"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print(f"[DEBUG] Token expired for user: {jwt_payload.get('sub', {}).get('username', 'unknown')}")
    return jsonify({"error": "Token has expired"}), 401

# Configure Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[RATELIMIT_DEFAULT],
    storage_uri=RATELIMIT_STORAGE_URL,
    strategy=RATELIMIT_STRATEGY
)

# Configure Socket.IO with explicit settings
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",  # Allow all origins for scanner routes
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False,
    always_connect=True,
    path='/socket.io/'
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
    try:
        data = request.get_json()
        target_url = data.get("url")
        target_url = sanitize_url(target_url)
        session_id = data.get("session_id")
        recaptcha_token = data.get("recaptcha_token")

        print(f"[*] Received scan request for URL: {target_url}")

        if not target_url:
            return jsonify({"error": "No URL provided"}), 400

        if not session_id:
            return jsonify({"error": "No session_id provided"}), 400

        # Verify reCAPTCHA
        is_captcha_valid, captcha_error = verify_recaptcha(recaptcha_token)
        if not is_captcha_valid:
            print(f"[!] reCAPTCHA verification failed: {captcha_error}")
            return jsonify({"error": f"reCAPTCHA verification failed: {captcha_error}"}), 400

        # Check weekly scan limit
        print(f"[*] Checking scan limit...")
        is_limited, limit_message = check_weekly_scan_limit(target_url)
        
        if (is_limited):
            print(f"[!] Scan limit reached: {limit_message}")
            return jsonify({"error": limit_message}), 429

        # Get the user's IP address and timestamp
        user_ip = get_client_ip(request)
        timestamp = datetime.now()

        # Generate scan_id first
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = session_id

        # Save scan request to database with scan_id
        try:
            db.save_scan_request(target_url, user_ip, timestamp, scan_id=scan_id)
            print(f"[+] Scan request saved to database with scan_id: {scan_id}")
        except Exception as e:
            print(f"[ERROR] Failed to save scan request: {str(e)}")
            return jsonify({"error": f"Failed to save scan request: {str(e)}"}), 500

        # Add URL to running scans
        running_scans[target_url] = datetime.now()

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
        user_input_url = data.get('targetUrl', '').strip()
        if not user_input_url:
            return jsonify({"error": "Target URL is required"}), 400

        # Normalize the URL for matching
        def normalize_url(url):
            # Remove protocol and trailing slash
            url = url.lower().strip()
            url = re.sub(r'^https?://', '', url)
            url = url.rstrip('/')
            return url

        normalized_input = normalize_url(user_input_url)

        # Try to find the protocol used in the most recent scan for this domain
        conn = db.get_connection()
        try:
            with conn.cursor() as cur:
                # Query using normalized URL
                cur.execute("""
                    SELECT url FROM scan_requests
                    WHERE LOWER(REPLACE(REPLACE(url, 'http://', ''), 'https://', '')) = %s
                    ORDER BY timestamp DESC
                    LIMIT 1
                """, (normalized_input,))
                row = cur.fetchone()
                if row:
                    target_url = row[0]  # Use the exact URL (with protocol) from the scan
                else:
                    # Fallback: use user input as-is, add https if missing protocol
                    if not user_input_url.startswith(('http://', 'https://')):
                        target_url = 'https://' + user_input_url
                    else:
                        target_url = user_input_url
        finally:
            db.put_connection(conn)

        # Save report request with the correct protocol
        try:
            timestamp = datetime.now()
            db.save_report_request(
                data['name'],
                data['email'],
                data.get('phone', ''),
                target_url,
                timestamp
            )
        except Exception as e:
            return jsonify({"error": f"Failed to save report request: {str(e)}"}), 500

        try:
            db.update_scan_summary(target_url=target_url)
        except Exception as e:
            return jsonify({"error": f"Failed to update marketing summary: {str(e)}"}), 500

        # Get report from database with improved URL matching
        try:
            conn = db.get_connection()
            try:
                with conn.cursor() as cur:
                    # Try multiple URL patterns
                    url_patterns = [
                        target_url,  # Exact match
                        target_url.rstrip('/'),  # Without trailing slash
                        normalize_url(target_url),  # Normalized (no protocol, no trailing slash)
                        f"http://{normalize_url(target_url)}",  # With http
                        f"https://{normalize_url(target_url)}"  # With https
                    ]
                    
                    for pattern in url_patterns:
                        cur.execute("""
                            SELECT content, target_url 
                            FROM zap_reports 
                            WHERE LOWER(REPLACE(REPLACE(target_url, 'http://', ''), 'https://', '')) = LOWER(%s)
                            AND report_type = 'html'
                            ORDER BY timestamp DESC 
                            LIMIT 1
                            """, (normalize_url(pattern),))
                        result = cur.fetchone()
                        if result:
                            return result[0], 200, {'Content-Type': 'text/html; charset=utf-8'}

                    return jsonify({
                        "error": "Scan report not found. Please ensure scan is completed."
                    }), 404
            finally:
                db.put_connection(conn)
        except Exception as e:
            return jsonify({"error": f"Failed to retrieve report: {str(e)}"}), 500

    except Exception as e:
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

@app.route("/api/auth/login", methods=["POST", "OPTIONS"])
@limiter.limit("5 per minute")
def login():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", SCANNER_CORS_ORIGINS[0])
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
        
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        username = data.get("username")
        password = data.get("password")
        
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400
            
        # Authenticate user
        user = db.authenticate_user(username, password)
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401
            
        # Create user identity string
        user_identity = json.dumps({
            "username": user["username"],
            "role": user["role"]
        })
        
        # Create tokens
        access_token = create_access_token(identity=user_identity)
        refresh_token = create_refresh_token(identity=user_identity)
        
        # Create response
        response = jsonify({
            "message": "Login successful",
            "user": {
                "username": user["username"],
                "role": user["role"]
            }
        })
        
        # Set cookies
        response.set_cookie(
            "access_token_cookie",
            access_token,
            httponly=True,
            secure=not FLASK_DEBUG,
            samesite="Lax",
            max_age=JWT_ACCESS_TOKEN_EXPIRES,
            domain=None,  # Let browser handle domain
            path="/"  # Set path to root
        )
        response.set_cookie(
            "refresh_token_cookie",
            refresh_token,
            httponly=True,
            secure=not FLASK_DEBUG,
            samesite="Lax",
            max_age=JWT_REFRESH_TOKEN_EXPIRES,
            domain=None,  # Let browser handle domain
            path="/"  # Set path to root
        )
        
        return response
        
    except Exception as e:
        if FLASK_DEBUG:
            print(f"[ERROR] Login failed: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        
        response = jsonify({"message": "Token refreshed"})
        response.set_cookie(
            "access_token_cookie",
            new_access_token,
            httponly=True,
            secure=not FLASK_DEBUG,
            samesite="Lax",
            max_age=3600
        )
        return response
    except Exception as e:
        return jsonify({"error": "Token refresh failed"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    response = jsonify({"message": "Logout successful"})
    response.delete_cookie("access_token_cookie")
    response.delete_cookie("refresh_token_cookie")
    return response

@app.route("/api/auth/verify", methods=["GET", "OPTIONS"])
@jwt_required(optional=True)
def verify_token():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        origin = request.headers.get("Origin")
        if origin in MARKETING_CORS_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
        return response
        
    try:
        if FLASK_DEBUG:
            print("[DEBUG] /api/auth/verify: Request headers =", dict(request.headers))
            print("[DEBUG] /api/auth/verify: Request cookies =", dict(request.cookies))
            
        identity = get_jwt_identity()
        
        if not identity:
            response = jsonify({"valid": False, "error": "No valid token"})
            origin = request.headers.get("Origin")
            if origin in MARKETING_CORS_ORIGINS:
                response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Vary"] = "Origin"
            return response, 401
            
        current_user = json.loads(identity)
        
        response = jsonify({
            "valid": True,
            "user": current_user
        })
        origin = request.headers.get("Origin")
        if origin in MARKETING_CORS_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
        return response
        
    except Exception as e:
        if FLASK_DEBUG:
            print(f"[ERROR] Token verification failed: {str(e)}")
        response = jsonify({"valid": False, "error": "Token verification failed"})
        origin = request.headers.get("Origin")
        if origin in MARKETING_CORS_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
        return response, 401

@app.route("/api/scan-report-summary", methods=["GET"])
@jwt_required()
def get_scan_report_summary():
    try:
        print("[DEBUG] Received request for scan report summary")
        identity = get_jwt_identity()
        current_user = json.loads(identity) if identity else None
        print(f"[DEBUG] Current user from JWT: {current_user}")
        
        if not current_user:
            print("[DEBUG] No user identity found in JWT")
            return jsonify({"error": "No user identity found"}), 401
            
        if current_user.get("role") != "admin":
            print(f"[DEBUG] User role '{current_user.get('role')}' is not admin")
            return jsonify({"error": "Unauthorized"}), 403
            
        print("[DEBUG] User is admin, proceeding with database query")
        conn = db.get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, scanned_on, ip_address, target_url, vuln_high, vuln_medium, vuln_low, vuln_info, 
                       user_email, user_name, user_phone, lead_status, last_updated
                FROM scan_report_summary
                ORDER BY scanned_on DESC NULLS LAST, id DESC
            """)
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            data = [dict(zip(columns, row)) for row in rows]
        db.put_connection(conn)
        print(f"[DEBUG] Successfully retrieved {len(data)} scan reports")
        return jsonify(data)
    except Exception as e:
        print(f"[ERROR] Failed to get scan report summary: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan-report-summary/<int:row_id>/lead-status", methods=["POST"])
def update_lead_status(row_id):
    try:
        new_status = request.json.get("lead_status")
        if not new_status:
            return jsonify({"error": "Missing lead_status"}), 400
        conn = db.get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scan_report_summary SET lead_status = %s, last_updated = CURRENT_TIMESTAMP WHERE id = %s",
                (new_status, row_id)
            )
            conn.commit()
        db.put_connection(conn)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Socket.IO connection event handlers
@socketio.on('connect')
def handle_connect():
    # Get the origin from headers
    origin = request.headers.get('Origin')
    
    # For marketing routes, only allow specific origins
    if origin in MARKETING_CORS_ORIGINS:
        return True
        
    # For scanner routes, allow all origins
    if not origin or origin not in MARKETING_CORS_ORIGINS:
        return True
        
    # Reject all other connections
    return False

@socketio.on('disconnect')
def handle_disconnect():
    # Only log in development mode
    if FLASK_DEBUG:
        print("[INFO] Client disconnected")
    # Remove any scans associated with this session
    disconnected_scans = [scan_id for scan_id, session_id in active_scans.items() 
                         if session_id == request.sid]
    for scan_id in disconnected_scans:
        active_scans.pop(scan_id, None)

@app.route("/api/network/start-scan", methods=["POST", "OPTIONS"])
def start_network_scan_endpoint():
    """Start a new network scan."""
    if request.method == "OPTIONS":
        return app.make_default_options_response()

    try:
        print("=== Starting network scan request ===")
        data = request.get_json()
        print(f"Request data: {data}")
        
        # Accept both 'ip' and 'ip_address' fields
        ip_address = data.get("ip_address") or data.get("ip")
        recaptcha_token = data.get("recaptcha_token")
        
        if not ip_address:
            print("Missing IP address in request data")
            return jsonify({"error": "Missing IP address"}), 400

        # Verify reCAPTCHA
        is_captcha_valid, captcha_error = verify_recaptcha(recaptcha_token)
        if not is_captcha_valid:
            print(f"[!] reCAPTCHA verification failed: {captcha_error}")
            return jsonify({"error": f"reCAPTCHA verification failed: {captcha_error}"}), 400

        requester_ip = get_client_ip(request)
        print(f"IP Address: {ip_address}, Requester IP: {requester_ip}")

        # Start the scan
        try:
            print("Attempting to start network scan...")
            success, message, scan_id = start_network_scan(ip_address, requester_ip)
            print(f"Network scan start result - Success: {success}, Message: {message}, Scan ID: {scan_id}")
        except Exception as e:
            print(f"Error in start_network_scan: {str(e)}")
            return jsonify({"error": "Failed to start scan"}), 500

        if not success:
            print(f"Scan start failed: {message}")
            return jsonify({"error": message}), 400

        print(f"Scan started successfully with ID: {scan_id}")
        response = jsonify({
            "message": "Scan started successfully",
            "scan_id": scan_id,
            "status": "queued"
        })
        return response

    except Exception as e:
        print(f"Error in start_network_scan_endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/network/scan/<scan_id>", methods=["GET"])
def get_network_scan_endpoint(scan_id):
    """Get the status and results of a network scan."""
    try:
        # Get requester IP from header or fallback to remote_addr
        requester_ip = request.headers.get('X-Requester-IP', request.remote_addr)
        print(f"Retrieving scan results for {scan_id} from {requester_ip}")
        
        # Use DatabaseHandler directly for consistency
        db_handler = DatabaseHandler()
        scan = db_handler.get_scan_by_id(scan_id, requester_ip)
        
        if not scan:
            print(f"Scan not found: {scan_id} for requester {requester_ip}")
            return jsonify({"error": "Scan not found"}), 404

        # Convert to proper response format
        response_data = {
            "scan_id": scan['scan_id'],
            "ip_address": scan['ip_address'],
            "scan_status": scan['scan_status'],
            "scan_results": scan['scan_results'],
            "error_message": scan['error_message'],
            "created_at": scan['created_at'].isoformat() if scan['created_at'] else None,
            "updated_at": scan['updated_at'].isoformat() if scan['updated_at'] else None
        }
        
        print(f"Successfully retrieved scan data for {scan_id}")
        return jsonify(response_data)

    except Exception as e:
        print(f"Error retrieving scan results: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/network/scans", methods=["GET"])
def list_network_scans():
    """List all network scans for the current requester."""
    try:
        requester_ip = request.headers.get('X-Requester-IP', request.remote_addr)
        print(f"Listing network scans for requester: {requester_ip}")
        
        # Use DatabaseHandler for consistency
        db_handler = DatabaseHandler()
        
        # Get all scans for this requester (combining different methods)
        try:
            conn = db_handler.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, 
                               error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE requester_ip = %s
                        ORDER BY created_at DESC
                        LIMIT 50
                    """, (requester_ip,))
                    
                    scans = []
                    for row in cur.fetchall():
                        scans.append({
                            "scan_id": row['scan_id'],
                            "ip_address": row['ip_address'],
                            "scan_status": row['scan_status'],
                            "scan_results": row['scan_results'],
                            "error_message": row['error_message'],
                            "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                            "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None
                        })
                    
                    print(f"Found {len(scans)} scans for requester {requester_ip}")
                    return jsonify({"scans": scans})
            finally:
                db_handler.put_connection(conn)
                
        except Exception as e:
            print(f"Database error listing scans: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": "Database error"}), 500

    except Exception as e:
        print(f"Error listing network scans: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

# Add IP range check middleware for marketing routes
@app.before_request
def check_ip_range():
    if request.path.startswith('/api/auth/') or \
       request.path == '/api/scan-report-summary' or \
       request.path == '/api/report-request':
        client_ip = get_client_ip(request)
        if not is_ip_allowed(client_ip):
            return jsonify({"error": "Access denied from this IP address"}), 403

def verify_recaptcha(recaptcha_token):
    """
    Verify Google reCAPTCHA token with Google's verification API
    Returns: (bool, str) - (is_valid, error_message)
    """
    if not RECAPTCHA_SECRET_KEY or RECAPTCHA_SECRET_KEY == "your_google_recaptcha_secret_key_here":
        # reCAPTCHA not configured - allow in development mode only
        if FLASK_DEBUG:
            logger.warning("reCAPTCHA not configured, allowing request in debug mode")
            return True, None
        else:
            return False, "reCAPTCHA verification is required but not configured"
    
    if not recaptcha_token:
        return False, "reCAPTCHA token is required"
    
    try:
        # Google reCAPTCHA verification endpoint
        verification_url = "https://www.google.com/recaptcha/api/siteverify"
        
        verification_data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_token,
            'remoteip': get_client_ip(request)  # Optional: include client IP
        }
        
        response = requests.post(verification_url, data=verification_data, timeout=10)
        response.raise_for_status()
        
        result = response.json()
        
        if result.get('success', False):
            # Check score for reCAPTCHA v3 (optional)
            score = result.get('score', 0.5)
            logger.info(f"reCAPTCHA verification successful, score: {score}")
            return True, None
        else:
            error_codes = result.get('error-codes', [])
            logger.warning(f"reCAPTCHA verification failed: {error_codes}")
            return False, f"reCAPTCHA verification failed: {', '.join(error_codes)}"
            
    except requests.exceptions.RequestException as e:
        logger.error(f"reCAPTCHA verification request failed: {str(e)}")
        return False, f"reCAPTCHA verification service unavailable"
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {str(e)}")
        return False, f"reCAPTCHA verification failed"

# Update the socket binding logic
if __name__ == "__main__":
    try:
        host = str(FLASK_HOST)
        if host == "0.0.0.0":
            print(f"[INFO] Server will be accessible from all network interfaces")
        elif not all(c.isdigit() or c == '.' for c in host.split('.')):
            print(f"[WARNING] Invalid IP address format: {host}, falling back to localhost")
            host = "127.0.0.1"
            
        print(f"[INFO] Starting server on {host}:{FLASK_PORT}")
        if FLASK_DEBUG:
            print(f"[INFO] Debug mode enabled")
        socketio.run(
            app,
            host=host,
            port=int(FLASK_PORT),
            debug=FLASK_DEBUG,
            use_reloader=False,
            log_output=FLASK_DEBUG  # Only enable logging in debug mode
        )
    except Exception as e:
        print(f"[ERROR] Failed to start server: {str(e)}")
        raise