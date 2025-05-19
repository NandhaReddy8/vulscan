import csv
import os
from db_handler import DatabaseHandler
import datetime
import json
from typing import Optional

db = DatabaseHandler()

# Define CSV file paths
SCAN_REQUESTS_FILE = "scan_requests.csv"
REPORT_REQUESTS_FILE = "report_requests.csv"

# Ensure the CSV files exist
def initialize_csv(file_path, headers):
    """Create a CSV file with headers if it doesn't exist."""
    if not os.path.exists(file_path):
        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)  # Write column headers

# Initialize CSV files
initialize_csv(SCAN_REQUESTS_FILE, ["scan_id", "url", "ip_address", "timestamp"])  # Updated headers
initialize_csv(REPORT_REQUESTS_FILE, ["Name", "Email", "Phone", "Target URL", "Timestamp"])

# Function to save a scan request
def save_scan_request(url, ip_address, timestamp, scan_id=None):
    """Save scan request to database"""
        conn = db.get_connection()
        try:
            with conn.cursor() as cur:
            # If timestamp is None, use current timestamp
            if timestamp is None:
                timestamp = datetime.datetime.now()
            
            # First check if scan_id already exists
            cur.execute("""
                SELECT id FROM scan_requests WHERE scan_id = %s
            """, (scan_id,))
            existing = cur.fetchone()
            
            if existing:
                # Update existing record
                cur.execute("""
                    UPDATE scan_requests 
                    SET url = %s, ip_address = %s, timestamp = %s
                    WHERE scan_id = %s
                    RETURNING id
                """, (url, ip_address, timestamp, scan_id))
            else:
                # Insert new record
                cur.execute("""
                    INSERT INTO scan_requests (scan_id, url, ip_address, timestamp)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (scan_id, url, ip_address, timestamp))
            
            result = cur.fetchone()
            conn.commit()  # Ensure the transaction is committed
            return result[0] if result else None
    except Exception as e:
        print(f"[ERROR] Failed to save scan request: {str(e)}")
        conn.rollback()
        raise
    finally:
        db.put_connection(conn)

# Function to save a report request
def save_report_request(name, email, phone, target_url, timestamp):
    """Save report request to database"""
    try:
        # Ensure protocol is present
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url  # Default to http, or use https if you prefer

        db.ensure_tables_exist()  # Ensure tables exist before operation
        conn = db.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO report_requests (name, email, phone, target_url, timestamp)
                    VALUES (%s, %s, %s, %s, %s)
                    """, (name, email, phone, target_url, timestamp))
            conn.commit()
        finally:
            db.put_connection(conn)
    except Exception as e:
        print(f"[ERROR] Failed to save report request: {str(e)}")
        raise

# Function to retrieve stored scan requests
def get_scan_requests():
    """Get all scan requests"""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT scan_id, url, ip_address, timestamp 
                FROM scan_requests 
                ORDER BY timestamp DESC
            """)
            return cur.fetchall()
    finally:
        db.put_connection(conn)

# Function to retrieve stored report requests
def get_report_requests():
    """Get all report requests"""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM report_requests ORDER BY timestamp DESC")
            return cur.fetchall()
    finally:
        db.put_connection(conn)

# Function to save scan results and update marketing summary
def save_scan_results(scan_id, target_url, results, context_name=None):
    """Save scan results and update marketing summary"""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            # Save scan results
            cur.execute("""
                INSERT INTO zap_results 
                (scan_id, target_url, results, timestamp)
                VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            """, (scan_id, target_url, json.dumps(results)))

            # Get the latest scan request info for this URL
            cur.execute("""
                SELECT timestamp, ip_address, url
                FROM scan_requests
                WHERE url = %s
                ORDER BY timestamp DESC
                LIMIT 1
            """, (target_url,))
            scan_row = cur.fetchone()
            if scan_row:
                scanned_on, ip_address, url = scan_row
            else:
                scanned_on, ip_address, url = None, None, target_url

            # Get vulnerability summary
            high = int(results.get("summary", {}).get("High", 0))
            medium = int(results.get("summary", {}).get("Medium", 0))
            low = int(results.get("summary", {}).get("Low", 0))
            info = int(results.get("summary", {}).get("Informational", 0))

            # Get the latest report request info for this URL (if any)
            cur.execute("""
                SELECT email, name, phone
                FROM report_requests
                WHERE target_url = %s
                ORDER BY timestamp DESC
                LIMIT 1
            """, (target_url,))
            report_row = cur.fetchone()
            if report_row:
                user_email, user_name, user_phone = report_row
            else:
                user_email, user_name, user_phone = None, None, None

            # Upsert into summary table (only one row per target_url)
            cur.execute("""
                INSERT INTO scan_report_summary (
                    scanned_on, ip_address, target_url,
                    vuln_high, vuln_medium, vuln_low, vuln_info,
                    user_email, user_name, user_phone, lead_status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                    COALESCE((SELECT lead_status FROM scan_report_summary WHERE target_url = %s), 'not_connected')
                )
                ON CONFLICT (target_url) DO UPDATE SET
                    scanned_on = EXCLUDED.scanned_on,
                    ip_address = EXCLUDED.ip_address,
                    vuln_high = EXCLUDED.vuln_high,
                    vuln_medium = EXCLUDED.vuln_medium,
                    vuln_low = EXCLUDED.vuln_low,
                    vuln_info = EXCLUDED.vuln_info,
                    user_email = EXCLUDED.user_email,
                    user_name = EXCLUDED.user_name,
                    user_phone = EXCLUDED.user_phone,
                    last_updated = CURRENT_TIMESTAMP
            """, (
                scanned_on, ip_address, target_url,
                high, medium, low, info,
                user_email, user_name, user_phone, target_url
            ))

        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to save scan results: {str(e)}")
        conn.rollback()
        raise
    finally:
        db.put_connection(conn)

# Function to save network scan results
def save_network_scan_results(*, scan_id: str, ip_address: str, scan_status: str, scan_results: Optional[dict] = None, error_message: Optional[str] = None, requester_ip: Optional[str] = None):
    """Save network scan results to database
    
    Args:
        scan_id: Unique identifier for the scan
        ip_address: Target IP address that was scanned
        scan_status: Current status of the scan ('pending', 'running', 'completed', 'failed')
        scan_results: Optional JSON results from the scan (dict or str)
        error_message: Optional error message if scan failed
        requester_ip: IP address of the person who requested the scan
    """
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            # Convert scan_results to JSON string if it's a dict
            scan_results_json = None
            if scan_results is not None:
                if isinstance(scan_results, dict):
                    try:
                        scan_results_json = json.dumps(scan_results)
                    except (TypeError, ValueError) as e:
                        print(f"[ERROR] Failed to serialize scan results: {str(e)}")
                        scan_results_json = json.dumps({"error": "Failed to serialize scan results"})
                elif isinstance(scan_results, str):
                    # If it's already a string, validate it's proper JSON
                    try:
                        # Try to parse and re-stringify to ensure valid JSON
                        scan_results_json = json.dumps(json.loads(scan_results))
                    except json.JSONDecodeError:
                        scan_results_json = json.dumps({"error": "Invalid JSON in scan results"})
                else:
                    scan_results_json = json.dumps({"error": "Invalid scan results format"})

            # Debug print
            print(f"[DEBUG] Saving scan results for {scan_id}:")
            print(f"Status: {scan_status}")
            print(f"Results type: {type(scan_results)}")
            print(f"JSON type: {type(scan_results_json)}")
            if scan_results_json:
                print(f"JSON preview: {scan_results_json[:100]}...")

            cur.execute("""
                INSERT INTO network_scan_results 
                (scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip)
                VALUES (%s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s)
                ON CONFLICT (scan_id) DO UPDATE SET
                    scan_status = EXCLUDED.scan_status,
                    scan_results = EXCLUDED.scan_results,
                    error_message = EXCLUDED.error_message,
                    scan_timestamp = CURRENT_TIMESTAMP,
                    requester_ip = EXCLUDED.requester_ip
            """, (scan_id, ip_address, scan_status, scan_results_json, error_message, requester_ip))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to save network scan results: {str(e)}")
        conn.rollback()
        raise
    finally:
        db.put_connection(conn)

# Function to get network scan results
def get_network_scan_results(scan_id, requester_ip):
    """Get network scan results if requester is authorized"""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT scan_results, scan_status, error_message, requester_ip
                FROM network_scan_results
                WHERE scan_id = %s
            """, (scan_id,))
            result = cur.fetchone()
            
            if not result:
                return None
                
            # Verify requester - only check if requester_ip is set in the database and not None
            stored_requester_ip = result[3]
            if stored_requester_ip is not None and stored_requester_ip != requester_ip:
                print(f"[WARNING] IP mismatch - Stored: {stored_requester_ip}, Request: {requester_ip}")
                return {"error": "Unauthorized access"}
            
            # Parse scan_results from JSON string
            scan_results = None
            if result[0]:
                try:
                    # First, ensure we have a string to parse
                    if isinstance(result[0], str):
                        raw_results = json.loads(result[0])
                    elif isinstance(result[0], dict):
                        raw_results = result[0]
                    else:
                        return {
                            "status": result[1],
                            "error": "Invalid scan results format",
                            "results": None
                        }

                    # Extract ports and services
                    open_ports = raw_results.get("open_ports", [])
                    services = raw_results.get("services", [])
                    
                    # Format ports for frontend
                    formatted_ports = []
                    
                    # If open_ports is a list of integers
                    if open_ports and isinstance(open_ports[0], int):
                        # Create a mapping of port numbers to service info
                        service_map = {s.get("port"): s for s in services if isinstance(s, dict)}
                        
                        for port_num in open_ports:
                            service_info = service_map.get(port_num, {})
                            formatted_ports.append({
                                "port": str(port_num),
                                "protocol": "tcp",
                                "state": service_info.get("state", "open"),
                                "service": service_info.get("service", "unknown")
                            })
                    # If open_ports is a list of dictionaries
                    elif open_ports and isinstance(open_ports[0], dict):
                        for port_info in open_ports:
                            formatted_ports.append({
                                "port": str(port_info.get("port", "")),
                                "protocol": "tcp",
                                "state": port_info.get("state", "open"),
                                "service": port_info.get("service", "unknown")
                            })

                    # Create the final formatted results
                    formatted_results = {
                        "summary": {
                            "total_ports": 100,  # Nmap -F scans top 100 ports
                            "open_ports": len(formatted_ports),
                            "scan_timestamp": datetime.datetime.now().isoformat()
                        },
                        "ports": formatted_ports,
                        "host_info": {
                            "hostname": raw_results.get("hostname", "Unknown"),
                            "ip": raw_results.get("ip", "Unknown")
                        },
                        "scan_time": str(raw_results.get("scan_time", "Unknown"))
                    }

                    scan_results = formatted_results

                except json.JSONDecodeError as e:
                    return {
                        "status": result[1],
                        "error": "Invalid scan results format",
                        "results": None
                    }
                except Exception as e:
                    import traceback
                    print(f"[ERROR] Error formatting scan results: {str(e)}")
                    return {
                        "status": result[1],
                        "error": f"Error formatting results: {str(e)}",
                        "results": None
                    }
                
            return {
                "status": result[1],
                "results": scan_results,
                "error": result[2]
            }
    except Exception as e:
        print(f"[ERROR] Failed to get network scan results: {str(e)}")
        return None
    finally:
        db.put_connection(conn)