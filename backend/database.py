import csv
import os
from db_handler import DatabaseHandler
import datetime
import json
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import DictCursor
import logging
from config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT

# Configure logging
logger = logging.getLogger(__name__)

# Database connection parameters from config
DB_PARAMS = {
    "dbname": DB_NAME,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "host": DB_HOST,
    "port": DB_PORT
}

logger.info(f"Using database: {DB_PARAMS['dbname']} on {DB_PARAMS['host']}:{DB_PARAMS['port']}")

@contextmanager
def get_db_connection():
    """Get a database connection with proper error handling."""
    conn = None
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        yield conn
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def create_scan_record(scan_id: str, ip_address: str, requester_ip: str) -> bool:
    """Create a new scan record with initial 'queued' status."""
    logger.info(f"Creating new scan record for scan_id: {scan_id}")
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO network_scan_results 
                    (scan_id, ip_address, scan_status, requester_ip, created_at, updated_at)
                    VALUES (%s, %s, 'queued', %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    RETURNING scan_id
                """, (scan_id, ip_address, requester_ip))
                
                if cur.fetchone():
                    conn.commit()
                    logger.info(f"Successfully created scan record for scan_id: {scan_id}")
                    return True
                return False
                
    except Exception as e:
        logger.error(f"Error creating scan record: {str(e)}")
        return False

def update_scan_status(scan_id: str, status: str, results: Optional[Dict] = None, error: Optional[str] = None) -> bool:
    """Update scan status and results in a single transaction."""
    logger.info(f"Updating scan status for scan_id: {scan_id} to {status}")
    
    try:
        # Convert results dict to JSON string if present
        results_json = json.dumps(results) if results is not None else None
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE network_scan_results 
                    SET scan_status = %s,
                        scan_results = COALESCE(%s::jsonb, scan_results),
                        error_message = COALESCE(%s, error_message),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = %s
                    RETURNING scan_id
                """, (status, results_json, error, scan_id))
                
                if cur.fetchone():
                    conn.commit()
                    logger.info(f"Successfully updated scan status for scan_id: {scan_id}")
                    return True
                logger.error(f"Scan {scan_id} not found during status update")
                return False
                
    except Exception as e:
        logger.error(f"Error updating scan status: {str(e)}")
        return False

def get_scan_by_id(scan_id: str, requester_ip: str) -> Optional[Dict[str, Any]]:
    """Get scan details by ID, ensuring requester authorization."""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute("""
                    SELECT scan_id, ip_address, scan_status, scan_results, 
                           error_message, created_at, updated_at
                    FROM network_scan_results
                    WHERE scan_id = %s AND requester_ip = %s
                """, (scan_id, requester_ip))
                
                scan = cur.fetchone()
                if scan:
                    return dict(scan)
                return None
                
    except Exception as e:
        logger.error(f"Error getting scan by ID: {str(e)}")
        return None

def get_active_scans(ip_address: str, requester_ip: str, minutes: int = 5) -> List[Dict[str, Any]]:
    """Get active scans for an IP address from a specific requester."""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute("""
                    SELECT scan_id, ip_address, scan_status, created_at, updated_at
                    FROM network_scan_results
                    WHERE ip_address = %s 
                    AND requester_ip = %s
                    AND created_at > NOW() - INTERVAL '%s minutes'
                    AND scan_status IN ('queued', 'running')
                    ORDER BY created_at DESC
                """, (ip_address, requester_ip, str(minutes)))
                
                return [dict(row) for row in cur.fetchall()]
                
    except Exception as e:
        logger.error(f"Error getting active scans: {str(e)}")
        return []

def get_recent_scans(ip_address: str, requester_ip: str, minutes: int = 5) -> List[Dict[str, Any]]:
    """Get recent scans for an IP address from a specific requester."""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute("""
                    SELECT scan_id, ip_address, scan_status, scan_results, 
                           error_message, created_at, updated_at
                    FROM network_scan_results
                    WHERE ip_address = %s 
                    AND requester_ip = %s
                    AND created_at > NOW() - INTERVAL %s MINUTE
                    ORDER BY created_at DESC
                """, (ip_address, requester_ip, minutes))
                
                return [dict(row) for row in cur.fetchall()]
                
    except Exception as e:
        logger.error(f"Error getting recent scans: {str(e)}")
        return []

# Initialize database tables
def initialize_tables():
    """Initialize database tables if they don't exist."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Create network_scan_results table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS network_scan_results (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT NOT NULL UNIQUE,
                        ip_address TEXT NOT NULL,
                        scan_status TEXT NOT NULL CHECK (scan_status IN ('queued', 'running', 'completed', 'failed', 'stopped')),
                        scan_results JSONB,
                        error_message TEXT,
                        requester_ip TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_network_scan_id ON network_scan_results(scan_id);
                    CREATE INDEX IF NOT EXISTS idx_network_scan_ip ON network_scan_results(ip_address);
                    CREATE INDEX IF NOT EXISTS idx_network_scan_status ON network_scan_results(scan_status);
                    CREATE INDEX IF NOT EXISTS idx_network_scan_timestamp ON network_scan_results(created_at);
                """)
                
                conn.commit()
                logger.info("Database tables initialized successfully")
                return True
                
    except Exception as e:
        logger.error(f"Error initializing database tables: {str(e)}")
        return False

# Create database handler instance (tables will be initialized in DatabaseHandler.__init__)
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
    """Save scan request to database (application scanner only)"""
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
    """Save (or update) a network scan result into the network_scan_results table."""
    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            # First check if record exists
            cur.execute("SELECT id FROM network_scan_results WHERE scan_id = %s", (scan_id,))
            existing = cur.fetchone()

            if existing:
                # Update existing record
                cur.execute("""
                    UPDATE network_scan_results 
                    SET ip_address = COALESCE(%s, ip_address),
                        scan_status = %s,
                        scan_results = COALESCE(%s, scan_results),
                        error_message = COALESCE(%s, error_message),
                        requester_ip = COALESCE(%s, requester_ip),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = %s
                    RETURNING id
                """, (ip_address, scan_status, scan_results, error_message, requester_ip, scan_id))
            else:
                # Insert new record
                cur.execute("""
                    INSERT INTO network_scan_results 
                    (scan_id, ip_address, scan_status, scan_results, error_message, requester_ip)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (scan_id, ip_address, scan_status, scan_results, error_message, requester_ip))

            result = cur.fetchone()
            conn.commit()
            
            if result:
                print(f"[INFO] Successfully saved scan results for scan_id: {scan_id}")
                return result[0]
            else:
                print(f"[WARNING] No result returned after saving scan_id: {scan_id}")
                return None

    except Exception as e:
        print(f"[ERROR] Failed to save network scan results for scan_id {scan_id}: {str(e)}")
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
                SELECT scan_id, ip_address, scan_status, scan_results, error_message, requester_ip, created_at, updated_at
                FROM network_scan_results
                WHERE scan_id = %s
            """, (scan_id,))
            row = cur.fetchone()
            if row:
                return {
                    "scan_id": row[0],
                    "ip_address": row[1],
                    "scan_status": row[2],
                    "scan_results": row[3],
                    "error_message": row[4],
                    "requester_ip": row[5],
                    "created_at": row[6],
                    "updated_at": row[7]
                }
            return None
    except Exception as e:
         print(f"[ERROR] Failed to get network scan results: {str(e)}")
         raise
    finally:
         db.put_connection(conn) 