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

    # Add methods to handle database operations