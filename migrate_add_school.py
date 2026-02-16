#!/usr/bin/env python3
"""
Migration script to add school column to users and item tables
"""
import os
import sqlite3

def run_school_migration():
    """Add school column to users and item tables"""
    try:
        # Get database URL
        db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')

        if db_url.startswith("postgresql://") or db_url.startswith("postgres://"):
            # Import psycopg2 only when needed
            import psycopg2
            import urllib.parse

            # Convert postgres:// to postgresql:// for consistency
            if db_url.startswith("postgres://"):
                db_url = db_url.replace("postgres://", "postgresql://", 1)

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

        elif db_url.startswith("sqlite:///"):
            # Handle SQLite database
            db_path = db_url.replace("sqlite:///", "")
            print(f"[MIGRATION] Connecting to SQLite database: {db_path}")

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Check if users table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            users_table_exists = cursor.fetchone()

            if users_table_exists:
                # Check if school column exists in users table
                cursor.execute("PRAGMA table_info(users)")
                columns = cursor.fetchall()
                column_names = [col[1] for col in columns]

                if 'school' not in column_names:
                    print("[MIGRATION] Adding school column to users table...")
                    cursor.execute("""
                        ALTER TABLE users
                        ADD COLUMN school VARCHAR(50) DEFAULT 'South Forsyth'
                    """)
                    print("[MIGRATION] Added school column to users table")
                else:
                    print("[MIGRATION] School column already exists in users table")
            else:
                print("[MIGRATION] Users table does not exist yet, skipping migration")

            # Check if item table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='item'")
            item_table_exists = cursor.fetchone()

            if item_table_exists:
                # Check if school column exists in item table
                cursor.execute("PRAGMA table_info(item)")
                columns = cursor.fetchall()
                column_names = [col[1] for col in columns]

                if 'school' not in column_names:
                    print("[MIGRATION] Adding school column to item table...")
                    cursor.execute("""
                        ALTER TABLE item
                        ADD COLUMN school VARCHAR(50) DEFAULT 'South Forsyth'
                    """)
                    print("[MIGRATION] Added school column to item table")
                else:
                    print("[MIGRATION] School column already exists in item table")
            else:
                print("[MIGRATION] Item table does not exist yet, skipping migration")

            conn.commit()
            conn.close()
            print("[MIGRATION] SQLite school migration completed successfully")

        else:
            print("[MIGRATION] Unsupported database type, skipping school migration")

    except Exception as e:
        print(f"[MIGRATION] School migration error: {e}")
        # Don't fail the app for migration issues
        pass

if __name__ == "__main__":
    run_school_migration()