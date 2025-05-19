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

# Function to save a report request (for example, from a marketing frontend)
def save_report_request(name, email, phone, target_url, timestamp=None):
    """Save a report request (for example, from a marketing frontend) into the report_requests table."""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            if timestamp is None:
                timestamp = datetime.datetime.now()
            cur.execute("""
                INSERT INTO report_requests (name, email, phone, target_url, timestamp)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (name, email, phone, target_url, timestamp))
            result = cur.fetchone()
            conn.commit()
            return result[0] if result else None
    except Exception as e:
        print(f"[ERROR] Failed to save report request: {str(e)}")
        conn.rollback()
        raise
    finally:
         db.put_connection(conn) 

# Function to retrieve scan requests (optionally filtered by scan_id)
def get_scan_requests(scan_id=None):
    """Retrieve scan requests (optionally filtered by scan_id) from the scan_requests table."""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            if scan_id is not None:
                cur.execute("""
                    SELECT scan_id, url, ip_address, timestamp FROM scan_requests WHERE scan_id = %s
                """, (scan_id,))
            else:
                cur.execute("""
                    SELECT scan_id, url, ip_address, timestamp FROM scan_requests ORDER BY timestamp DESC
                """)
            rows = cur.fetchall()
            return [{"scan_id": r[0], "url": r[1], "ip_address": r[2], "timestamp": r[3]} for r in rows]
    except Exception as e:
         print(f"[ERROR] Failed to get scan requests: {str(e)}")
         raise
    finally:
         db.put_connection(conn) 

# Function to save (or update) a network scan result (for example, from a scan_network call)
def save_network_scan_results(scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip):
    """Save (or update) a network scan result (scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip) into the network_scan_results table."""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO network_scan_results (scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    scan_timestamp = EXCLUDED.scan_timestamp,
                    scan_status = EXCLUDED.scan_status,
                    scan_results = EXCLUDED.scan_results,
                    error_message = EXCLUDED.error_message,
                    requester_ip = EXCLUDED.requester_ip
                RETURNING id
            """, (scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip))
            result = cur.fetchone()
            conn.commit()
            return result[0] if result else None
    except Exception as e:
         print(f"[ERROR] Failed to save network scan results: {str(e)}")
         conn.rollback()
         raise
    finally:
         db.put_connection(conn) 

# Function to retrieve (or query) a network scan result (by scan_id) from the network_scan_results table
def get_network_scan_results(scan_id):
    """Retrieve (or query) a network scan result (by scan_id) from the network_scan_results table."""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip
                FROM network_scan_results
                WHERE scan_id = %s
            """, (scan_id,))
            row = cur.fetchone()
            if row:
                 return {"scan_id": row[0], "ip_address": row[1], "scan_timestamp": row[2], "scan_status": row[3], "scan_results": row[4], "error_message": row[5], "requester_ip": row[6]}
            return None
    except Exception as e:
         print(f"[ERROR] Failed to get network scan results: {str(e)}")
         raise
    finally:
         db.put_connection(conn) 