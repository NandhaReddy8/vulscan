import os
import psycopg2
from psycopg2.extras import DictCursor
from psycopg2 import pool
from dotenv import load_dotenv
import logging
import psycopg2.pool
import bcrypt
import csv
import datetime
import json
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)
load_dotenv()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash"""
    try:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception as e:
        print(f"[ERROR] Password verification failed: {str(e)}")
        return False

class DatabaseHandler:
    def __init__(self):
        self.pool = pool.SimpleConnectionPool(
            minconn=1,
            maxconn=20,
            dbname=os.getenv("DB_NAME", "webscanner"),  # Updated default
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            connect_timeout=10,  # 10 second connection timeout
            options='-c statement_timeout=30000'  # 30 second statement timeout
        )
        self.initialize_tables()
        self._conn = None  # Add connection attribute for context manager
        
        # Initialize CSV files
        self.SCAN_REQUESTS_FILE = "scan_requests.csv"
        self.REPORT_REQUESTS_FILE = "report_requests.csv"
        self._initialize_csv_files()

    def __enter__(self):
        """Context manager entry - get a connection and cursor"""
        self._conn = self.get_connection()
        self._cursor = self._conn.cursor(cursor_factory=DictCursor)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - handle transaction and cleanup"""
        try:
            if exc_type is not None:
                # An exception occurred, rollback
                self._conn.rollback()
            else:
                # No exception, commit
                self._conn.commit()
        finally:
            # Always close cursor and return connection to pool
            if hasattr(self, '_cursor'):
                self._cursor.close()
            if self._conn:
                self.put_connection(self._conn)
            self._conn = None

    def get_connection(self):
        return self.pool.getconn()

    def put_connection(self, conn):
        self.pool.putconn(conn)

    def _initialize_csv_files(self):
        """Initialize CSV files if they don't exist."""
        def initialize_csv(file_path, headers):
            """Create a CSV file with headers if it doesn't exist."""
            if not os.path.exists(file_path):
                with open(file_path, "w", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow(headers)  # Write column headers
        
        # Initialize CSV files
        initialize_csv(self.SCAN_REQUESTS_FILE, ["scan_id", "url", "ip_address", "timestamp"])
        initialize_csv(self.REPORT_REQUESTS_FILE, ["Name", "Email", "Phone", "Target URL", "Timestamp"])

    def check_table_exists(self, table_name):
        """Check if a table exists in the database"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = %s
                    );
                """, (table_name,))
                return cur.fetchone()[0]
        finally:
            self.put_connection(conn)

    def create_table(self, table_sql):
        """Create a table using the provided SQL"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(table_sql)
            conn.commit()
            print(f"[DB] Table created successfully")
        except Exception as e:
            print(f"[DB ERROR] Failed to create table: {str(e)}")
            conn.rollback()
            raise
        finally:
            self.put_connection(conn)

    def initialize_tables(self):
        """Create necessary tables if they don't exist"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor() as cur:
                    # Create users table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id SERIAL PRIMARY KEY,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            email VARCHAR(255) UNIQUE NOT NULL,
                            password_hash VARCHAR(255) NOT NULL,
                            role VARCHAR(20) NOT NULL DEFAULT 'user',
                            is_active BOOLEAN DEFAULT true,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP,
                            CONSTRAINT valid_role CHECK (role IN ('admin', 'user'))
                        )
                    """)
                    conn.commit()

                    # Create scan_requests table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS scan_requests (
                            id SERIAL PRIMARY KEY,
                            scan_id TEXT UNIQUE NOT NULL,
                            url TEXT NOT NULL,
                            ip_address TEXT NOT NULL,
                            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            scan_type TEXT NOT NULL DEFAULT 'application'
                        )
                    """)
                    conn.commit()

                    # Create report_requests table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS report_requests (
                            id SERIAL PRIMARY KEY,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL,
                            phone TEXT,
                            target_url TEXT NOT NULL,
                            timestamp TIMESTAMP NOT NULL
                        )
                    """)
                    conn.commit()

                    # Create zap_results table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS zap_results (
                            id SERIAL PRIMARY KEY,
                            scan_id TEXT NOT NULL,
                            target_url TEXT NOT NULL,
                            results JSONB NOT NULL,
                            timestamp TIMESTAMP NOT NULL
                        )
                    """)
                    conn.commit()

                    # Create zap_reports table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS zap_reports (
                            id SERIAL PRIMARY KEY,
                            scan_id TEXT NOT NULL,
                            target_url TEXT NOT NULL,
                            report_type TEXT NOT NULL,
                            content TEXT NOT NULL,
                            timestamp TIMESTAMP NOT NULL
                        )
                    """)
                    conn.commit()

                    # Create scan_report_summary table
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS scan_report_summary (
                            id SERIAL PRIMARY KEY,
                            scanned_on TIMESTAMP,
                            ip_address VARCHAR(45),
                            target_url TEXT UNIQUE,
                            vuln_high INT DEFAULT 0,
                            vuln_medium INT DEFAULT 0,
                            vuln_low INT DEFAULT 0,
                            vuln_info INT DEFAULT 0,
                            user_email TEXT,
                            user_name TEXT,
                            user_phone TEXT,
                            lead_status TEXT DEFAULT 'not_connected',
                            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    conn.commit()

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
                    conn.commit()

                    # Create indexes only if tables and columns exist
                    # Check and create network_scan_results indexes
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT 1 
                            FROM information_schema.columns 
                            WHERE table_name = 'network_scan_results' 
                            AND column_name = 'scan_id'
                        )
                    """)
                    if cur.fetchone()[0]:
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_network_scan_id ON network_scan_results(scan_id)")
                        conn.commit()

                    cur.execute("""
                        SELECT EXISTS (
                            SELECT 1 
                            FROM information_schema.columns 
                            WHERE table_name = 'network_scan_results' 
                            AND column_name = 'ip_address'
                        )
                    """)
                    if cur.fetchone()[0]:
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_network_scan_ip ON network_scan_results(ip_address)")
                        conn.commit()

                    cur.execute("""
                        SELECT EXISTS (
                            SELECT 1 
                            FROM information_schema.columns 
                            WHERE table_name = 'network_scan_results' 
                            AND column_name = 'scan_status'
                        )
                    """)
                    if cur.fetchone()[0]:
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_network_scan_status ON network_scan_results(scan_status)")
                        conn.commit()

                    cur.execute("""
                        SELECT EXISTS (
                            SELECT 1 
                            FROM information_schema.columns 
                            WHERE table_name = 'network_scan_results' 
                            AND column_name = 'created_at'
                        )
                    """)
                    if cur.fetchone()[0]:
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_network_scan_created ON network_scan_results(created_at)")
                        conn.commit()

                    # Check and create scan_requests index
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT 1 
                            FROM information_schema.columns 
                            WHERE table_name = 'scan_requests' 
                            AND column_name = 'scan_id'
                        )
                    """)
                    if cur.fetchone()[0]:
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_requests_scan_id ON scan_requests(scan_id)")
                        conn.commit()

                    print("[+] Database tables initialized successfully")
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to initialize tables: {str(e)}")
            raise

    def ensure_tables_exist(self):
        """Ensure all required tables exist with correct schema"""
        try:
            # First create tables if they don't exist
            self.initialize_tables()
            
            # Then check if network_scan_results needs to be altered
            conn = self.get_connection()
            try:
                with conn.cursor() as cur:
                    # Check if scan_id has unique constraint
                    cur.execute("""
                        SELECT COUNT(*)
                        FROM information_schema.table_constraints tc
                        JOIN information_schema.constraint_column_usage ccu
                            ON tc.constraint_name = ccu.constraint_name
                        WHERE tc.table_name = 'network_scan_results'
                        AND tc.constraint_type = 'UNIQUE'
                        AND ccu.column_name = 'scan_id'
                    """)
                    has_unique = cur.fetchone()[0] > 0
                    
                    if not has_unique:
                        print("[*] Adding unique constraint to network_scan_results table...")
                        # Add unique constraint without dropping the table
                        cur.execute("""
                            ALTER TABLE network_scan_results 
                            ADD CONSTRAINT network_scan_results_scan_id_key UNIQUE (scan_id)
                        """)
                        conn.commit()
                        print("[+] Added unique constraint to network_scan_results table")
            finally:
                self.put_connection(conn)
                
        except Exception as e:
            print(f"[ERROR] Failed to ensure tables exist: {str(e)}")
            raise

    def update_scan_summary(self, scan_id=None, target_url=None):
        """Update marketing summary table after scan or report request"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                # Get latest scan_request for this URL
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

                # Get latest zap_results for this URL
                cur.execute("""
                    SELECT results
                    FROM zap_results
                    WHERE target_url = %s
                    ORDER BY timestamp DESC
                    LIMIT 1
                """, (target_url,))
                zap_row = cur.fetchone()
                if zap_row and zap_row[0]:
                    results = zap_row[0]
                    high = int(results.get("summary", {}).get("High", 0))
                    medium = int(results.get("summary", {}).get("Medium", 0))
                    low = int(results.get("summary", {}).get("Low", 0))
                    info = int(results.get("summary", {}).get("Informational", 0))
                else:
                    high = medium = low = info = 0

                # Get latest report_request for this URL
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
                        user_email, user_name, user_phone, lead_status, last_updated
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE((SELECT lead_status FROM scan_report_summary WHERE target_url = %s), 'not_connected'), CURRENT_TIMESTAMP)
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
            conn.rollback()
            raise
        finally:
            self.put_connection(conn)

    def authenticate_user(self, username: str, password: str) -> dict:
        """Authenticate a user and return user info if successful"""
        print(f"[DEBUG] Attempting to authenticate user: {username}")
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                # First get the user and their password hash
                cur.execute("""
                    SELECT id, username, email, role, is_active, password_hash
                    FROM users
                    WHERE username = %s AND is_active = true
                """, (username,))
                user = cur.fetchone()
                
                if not user:
                    print(f"[DEBUG] User not found or not active: {username}")
                    return None
                    
                print(f"[DEBUG] Found user: {user[1]} (role: {user[3]})")
                print(f"[DEBUG] Stored hash: {user[5]}")
                
                is_valid = verify_password(password, user[5])
                print(f"[DEBUG] Password verification result: {is_valid}")
                
                if is_valid:
                    # Update last login
                    cur.execute("""
                        UPDATE users 
                        SET last_login = CURRENT_TIMESTAMP 
                        WHERE id = %s
                    """, (user[0],))
                    conn.commit()
                    print(f"[DEBUG] Authentication successful for user: {username}")
                    
                    return {
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'role': user[3]
                    }
                print(f"[DEBUG] Password verification failed for user: {username}")
                return None
        except Exception as e:
            print(f"[ERROR] Authentication failed: {str(e)}")
            raise
        finally:
            self.put_connection(conn)

    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> bool:
        """Create a new user"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (username, email, hash_password(password), role))
                user_id = cur.fetchone()[0]
                conn.commit()
                return user_id
        except psycopg2.IntegrityError as e:
            print(f"[ERROR] User creation failed - duplicate username/email: {str(e)}")
            return None
        except Exception as e:
            print(f"[ERROR] User creation failed: {str(e)}")
            raise
        finally:
            self.put_connection(conn)

    def get_recent_scans(self, limit=10):
        """Get recent network scans"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (limit,))
                    return cur.fetchall()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get recent scans: {str(e)}")
            return []

    def get_scan_by_id(self, scan_id, requester_ip):
        """Get scan details by ID and ensure requester authorization"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE scan_id = %s AND requester_ip = %s
                    """, (scan_id, requester_ip))
                    return cur.fetchone()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get scan by ID: {str(e)}")
            return None

    def get_scans_by_ip(self, ip_address, requester_ip, limit=10):
        """Get scans for a specific IP address"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE ip_address = %s AND requester_ip = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (ip_address, requester_ip, limit))
                    return cur.fetchall()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get scans by IP: {str(e)}")
            return []

    def get_scans_by_status(self, status, requester_ip, limit=10):
        """Get scans by status"""
        conn = None
        try:
            conn = self.get_connection()
            if not conn:
                print(f"[ERROR] Failed to get database connection for status query")
                return []
                
            with conn.cursor(cursor_factory=DictCursor) as cur:
                # Set a query timeout to prevent hanging
                cur.execute("SET statement_timeout = '30s'")
                cur.execute("""
                    SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                    FROM network_scan_results
                    WHERE scan_status = %s AND requester_ip = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                """, (status, requester_ip, limit))
                result = cur.fetchall()
                print(f"[DEBUG] Found {len(result)} scans with status '{status}' for requester {requester_ip}")
                return result
        except Exception as e:
            print(f"[ERROR] Failed to get scans by status '{status}': {str(e)}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            return []
        finally:
            if conn:
                try:
                    self.put_connection(conn)
                except Exception as e:
                    print(f"[ERROR] Failed to return connection to pool: {str(e)}")

    def get_scans_by_time_range(self, start_time, end_time, requester_ip, limit=10):
        """Get scans within a time range"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE created_at BETWEEN %s AND %s AND requester_ip = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (start_time, end_time, requester_ip, limit))
                    return cur.fetchall()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get scans by time range: {str(e)}")
            return []

    def get_scans_last_24h(self, requester_ip, limit=10):
        """Get scans from the last 24 hours"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE created_at >= NOW() - INTERVAL '24 hours' AND requester_ip = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (requester_ip, limit))
                    return cur.fetchall()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get scans from last 24h: {str(e)}")
            return []

    def get_scans_last_7d(self, requester_ip, limit=10):
        """Get scans from the last 7 days"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE created_at >= NOW() - INTERVAL '7 days' AND requester_ip = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (requester_ip, limit))
                    return cur.fetchall()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get scans from last 7d: {str(e)}")
            return []

    def get_scans_last_30d(self, requester_ip, limit=10):
        """Get scans from the last 30 days"""
        try:
            conn = self.get_connection()
            try:
                with conn.cursor(cursor_factory=DictCursor) as cur:
                    cur.execute("""
                        SELECT scan_id, ip_address, scan_status, scan_results, error_message, created_at, updated_at
                        FROM network_scan_results
                        WHERE created_at >= NOW() - INTERVAL '30 days' AND requester_ip = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (requester_ip, limit))
                    return cur.fetchall()
            finally:
                self.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to get scans from last 30d: {str(e)}")
            return []

    def create_scan_record(self, scan_id: str, ip_address: str, requester_ip: str) -> bool:
        """Create a new scan record with initial 'queued' status."""
        print(f"[INFO] Creating new scan record for scan_id: {scan_id}")
        
        try:
            conn = self.get_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO network_scan_results 
                        (scan_id, ip_address, scan_status, requester_ip, created_at, updated_at)
                        VALUES (%s, %s, 'queued', %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        RETURNING scan_id
                    """, (scan_id, ip_address, requester_ip))
                    
                    if cur.fetchone():
                        conn.commit()
                        print(f"[INFO] Successfully created scan record for scan_id: {scan_id}")
                        return True
                    return False
            finally:
                self.put_connection(conn)
                    
        except Exception as e:
            print(f"[ERROR] Error creating scan record: {str(e)}")
            return False

    def update_scan_status(self, scan_id: str, status: str, results: Optional[dict] = None, error: Optional[str] = None) -> bool:
        """Update scan status and results in a single transaction."""
        print(f"[INFO] Updating scan status for scan_id: {scan_id} to {status}")
        
        try:
            # Convert results dict to JSON string if present
            import json
            results_json = json.dumps(results) if results is not None else None
            
            conn = self.get_connection()
            try:
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
                        print(f"[INFO] Successfully updated scan status for scan_id: {scan_id}")
                        return True
                    print(f"[ERROR] Scan {scan_id} not found during status update")
                    return False
            finally:
                self.put_connection(conn)
                    
        except Exception as e:
            print(f"[ERROR] Error updating scan status: {str(e)}")
            return False

    def get_active_scans_by_ip(self, ip_address: str, requester_ip: str, minutes: int = 5):
        """Get active scans for an IP address from a specific requester."""
        try:
            conn = self.get_connection()
            try:
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
            finally:
                self.put_connection(conn)
                    
        except Exception as e:
            print(f"[ERROR] Error getting active scans: {str(e)}")
            return []

    def get_recent_scans_by_ip(self, ip_address: str, requester_ip: str, minutes: int = 5):
        """Get recent scans for an IP address from a specific requester."""
        try:
            conn = self.get_connection()
            try:
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
            finally:
                self.put_connection(conn)
                    
        except Exception as e:
            print(f"[ERROR] Error getting recent scans: {str(e)}")
            return []

    def save_scan_request(self, url, ip_address, timestamp, scan_id=None):
        """Save scan request to database (application scanner only)"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                # If timestamp is None, use current timestamp
                if timestamp is None:
                    import datetime
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
            self.put_connection(conn)

    def save_report_request(self, name, email, phone, target_url, timestamp=None):
        """Save a report request (for example, from a marketing frontend) into the report_requests table."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                if timestamp is None:
                    import datetime
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
             self.put_connection(conn) 

    def get_scan_requests(self, scan_id=None):
        """Retrieve scan requests (optionally filtered by scan_id) from the scan_requests table."""
        conn = self.get_connection()
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
             self.put_connection(conn) 

    def save_network_scan_results(self, scan_id, ip_address, scan_timestamp, scan_status, scan_results, error_message, requester_ip):
        """Save (or update) a network scan result into the network_scan_results table."""
        conn = self.get_connection()
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
            self.put_connection(conn)

    def get_network_scan_results(self, scan_id):
        """Retrieve (or query) a network scan result (by scan_id) from the network_scan_results table."""
        conn = self.get_connection()
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
             self.put_connection(conn)