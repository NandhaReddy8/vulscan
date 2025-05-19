import os
import psycopg2
from psycopg2.extras import DictCursor
from psycopg2 import pool
from dotenv import load_dotenv
import json
from datetime import datetime
import logging
import psycopg2.pool
import bcrypt

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
            port=os.getenv("DB_PORT", "5432")
        )
        self.initialize_tables()

    def get_connection(self):
        return self.pool.getconn()

    def put_connection(self, conn):
        self.pool.putconn(conn)

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
        create_tables_sql = """
        -- Create users table for authentication
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
        );

        -- Create scan_requests table with scan_id column
        CREATE TABLE IF NOT EXISTS scan_requests (
            id SERIAL PRIMARY KEY,
            scan_id TEXT UNIQUE NOT NULL,  -- Add scan_id column for external reference
            url TEXT,
            ip_address TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        -- Create report_requests table
        CREATE TABLE IF NOT EXISTS report_requests (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            target_url TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
        );

        -- Create zap_results table
        CREATE TABLE IF NOT EXISTS zap_results (
            id SERIAL PRIMARY KEY,
            scan_id TEXT NOT NULL,
            target_url TEXT NOT NULL,
            results JSONB NOT NULL,
            timestamp TIMESTAMP NOT NULL
        );

        -- Create zap_reports table
        CREATE TABLE IF NOT EXISTS zap_reports (
            id SERIAL PRIMARY KEY,
            scan_id TEXT NOT NULL,
            target_url TEXT NOT NULL,
            report_type TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
        );

        -- Create marketing summary table
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
        );

        -- Create network_scan_results table (after scan_requests table exists)
        CREATE TABLE IF NOT EXISTS network_scan_results (
            id SERIAL PRIMARY KEY,
            scan_id TEXT NOT NULL UNIQUE,  -- Add UNIQUE constraint
            ip_address TEXT NOT NULL,
            scan_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            scan_status TEXT NOT NULL,     -- 'pending', 'running', 'completed', 'failed'
            scan_results JSONB,            -- Store Nmap results in JSON format
            error_message TEXT,            -- Store any error messages
            requester_ip TEXT NOT NULL,    -- IP address of the person who requested the scan
            FOREIGN KEY (scan_id) REFERENCES scan_requests(scan_id) ON DELETE CASCADE
        );

        -- Add indexes for faster lookups (after all tables exist)
        CREATE INDEX IF NOT EXISTS idx_network_scan_id ON network_scan_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_network_scan_ip ON network_scan_results(ip_address);
        CREATE INDEX IF NOT EXISTS idx_scan_requests_scan_id ON scan_requests(scan_id);
        """
        
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                # First create all tables
                for statement in create_tables_sql.split(';'):
                    if statement.strip():
                        try:
                        cur.execute(statement)
                            conn.commit()  # Commit after each statement
                        except Exception as e:
                            print(f"[WARNING] Error executing statement: {str(e)}")
                            conn.rollback()
                            raise
                
                # Then create default admin user if not exists
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role)
                    SELECT 'admin', 'admin@virtuestech.com', %s, 'admin'
                    WHERE NOT EXISTS (
                        SELECT 1 FROM users WHERE username = 'admin'
                    )
                """, (hash_password('admin123'),))
                
            conn.commit()
                print("[+] Database tables initialized successfully")
        except Exception as e:
            print(f"[ERROR] Failed to initialize tables: {str(e)}")
            conn.rollback()
            raise
        finally:
            self.put_connection(conn)

    def ensure_tables_exist(self):
        """Ensure all required tables exist with correct schema"""
        try:
            # First create tables if they don't exist
            self.initialize_tables()
            
            # Then check if network_scan_results needs to be recreated
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
                        print("[*] Recreating network_scan_results table with unique constraint...")
                        # Drop existing table
                        cur.execute("DROP TABLE IF EXISTS network_scan_results CASCADE")
                        # Recreate table with unique constraint
                        cur.execute("""
                            CREATE TABLE network_scan_results (
                                id SERIAL PRIMARY KEY,
                                scan_id TEXT NOT NULL UNIQUE,
                                ip_address TEXT NOT NULL,
                                scan_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                scan_status TEXT NOT NULL,
                                scan_results JSONB,
                                error_message TEXT,
                                requester_ip TEXT NOT NULL,
                                FOREIGN KEY (scan_id) REFERENCES scan_requests(scan_id) ON DELETE CASCADE
                            )
                        """)
                        # Recreate indexes
                        cur.execute("CREATE INDEX idx_network_scan_id ON network_scan_results(scan_id)")
                        cur.execute("CREATE INDEX idx_network_scan_ip ON network_scan_results(ip_address)")
                        conn.commit()
                        print("[+] network_scan_results table recreated successfully")
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
            print(f"[+] Marketing summary updated for URL: {target_url}")
        except Exception as e:
            print(f"[ERROR] Failed to update marketing summary: {str(e)}")
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