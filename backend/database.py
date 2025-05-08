import csv
import os
from db_handler import DatabaseHandler

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
initialize_csv(SCAN_REQUESTS_FILE, ["url", "ip_address", "timestamp"])  # Changed headers to match
initialize_csv(REPORT_REQUESTS_FILE, ["Name", "Email", "Phone", "Target URL", "Timestamp"])

# Function to save a scan request
def save_scan_request(url, ip_address, timestamp):
    """Save scan request to database"""
    try:
        db.ensure_tables_exist()  # Ensure tables exist before operation
        conn = db.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_requests (url, ip_address, timestamp)
                    VALUES (%s, %s, %s)
                    """, (url, ip_address, timestamp))
            conn.commit()
        finally:
            db.put_connection(conn)
    except Exception as e:
        print(f"[ERROR] Failed to save scan request: {str(e)}")
        raise

# Function to save a report request
def save_report_request(name, email, phone, target_url, timestamp):
    """Save report request to database"""
    try:
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
            cur.execute("SELECT * FROM scan_requests ORDER BY timestamp DESC")
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
                    user_email, user_name, user_phone
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (target_url) DO UPDATE SET
                    scanned_on = EXCLUDED.scanned_on,
                    ip_address = EXCLUDED.ip_address,
                    vuln_high = EXCLUDED.vuln_high,
                    vuln_medium = EXCLUDED.vuln_medium,
                    vuln_low = EXCLUDED.vuln_low,
                    vuln_info = EXCLUDED.vuln_info,
                    user_email = EXCLUDED.user_email,
                    user_name = EXCLUDED.user_name,
                    user_phone = EXCLUDED.user_phone
            """, (
                scanned_on, ip_address, target_url,
                high, medium, low, info,
                user_email, user_name, user_phone
            ))

        conn.commit()
        print(f"[+] Scan results and marketing summary saved for {target_url}")
    except Exception as e:
        print(f"[ERROR] Failed to save scan results: {str(e)}")
        conn.rollback()
        raise
    finally:
        db.put_connection(conn)