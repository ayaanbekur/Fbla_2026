#!/usr/bin/env python3
"""
Migration script to add school column to users and item tables
"""
import os
import psycopg2
import urllib.parse

def run_school_migration():
    """Add school column to users and item tables"""
    try:
        # Get database URL
        db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')

        if db_url.startswith("postgresql://"):
            # Parse PostgreSQL URL
            parsed = urllib.parse.urlparse(db_url)
            dbname = parsed.path.lstrip('/')
            user = parsed.username
            password = parsed.password
            host = parsed.hostname
            port = parsed.port or 5432

            print(f"[MIGRATION] Connecting to PostgreSQL database: {host}:{port}/{dbname}")

            # Connect to PostgreSQL
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port,
                sslmode='require' if 'sslmode=require' in db_url else 'prefer'
            )
            cursor = conn.cursor()

            # Add school column to users table if it doesn't exist
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'school'
            """)
            if not cursor.fetchone():
                print("[MIGRATION] Adding school column to users table...")
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN school VARCHAR(50) DEFAULT 'South Forsyth'
                """)
                print("[MIGRATION] Added school column to users table")
            else:
                print("[MIGRATION] School column already exists in users table")

            # Add school column to item table if it doesn't exist
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'item' AND column_name = 'school'
            """)
            if not cursor.fetchone():
                print("[MIGRATION] Adding school column to item table...")
                cursor.execute("""
                    ALTER TABLE item
                    ADD COLUMN school VARCHAR(50) DEFAULT 'South Forsyth'
                """)
                print("[MIGRATION] Added school column to item table")
            else:
                print("[MIGRATION] School column already exists in item table")

            conn.commit()
            conn.close()
            print("[MIGRATION] School migration completed successfully")

        else:
            print("[MIGRATION] Not a PostgreSQL database, skipping school migration")

    except Exception as e:
        print(f"[MIGRATION] School migration error: {e}")
        # Don't fail the app for migration issues
        pass

if __name__ == "__main__":
    run_school_migration()