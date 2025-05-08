import os
import psycopg2
from psycopg2.extras import DictCursor
from psycopg2 import pool
from dotenv import load_dotenv
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
load_dotenv()

class DatabaseHandler:
    def __init__(self):
        self.pool = pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT")
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
        -- Create scan_requests table
        CREATE TABLE IF NOT EXISTS scan_requests (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
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
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                # Split SQL into individual statements
                for statement in create_tables_sql.split(';'):
                    if statement.strip():
                        cur.execute(statement)
            conn.commit()
            print("[+] Database tables initialized")
        except Exception as e:
            print(f"[ERROR] Failed to initialize tables: {str(e)}")
            conn.rollback()
            raise
        finally:
            self.put_connection(conn)

    def ensure_tables_exist(self):
        """Check and create tables if they don't exist"""
        try:
            self.initialize_tables()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to ensure tables exist: {str(e)}")
            return False

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
                        user_email, user_name, user_phone, last_updated
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
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
                    user_email, user_name, user_phone
                ))
            conn.commit()
            print(f"[+] Marketing summary updated for URL: {target_url}")
        except Exception as e:
            print(f"[ERROR] Failed to update marketing summary: {str(e)}")
            conn.rollback()
            raise
        finally:
            self.put_connection(conn)