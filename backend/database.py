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

# Function to delete all scan requests