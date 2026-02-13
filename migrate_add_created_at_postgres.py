import os
import psycopg2
from datetime import datetime

# Get database URL from environment
db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Extract connection parameters from URL
if db_url.startswith("postgresql://"):
    # Parse PostgreSQL URL
    import urllib.parse
    parsed = urllib.parse.urlparse(db_url)
    dbname = parsed.path.lstrip('/')
    user = parsed.username
    password = parsed.password
    host = parsed.hostname
    port = parsed.port or 5432

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

    # Check if column exists
    cursor.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'created_at'
    """)
    exists = cursor.fetchone()

    if not exists:
        try:
            # Add the column with default timestamp
            cursor.execute("""
                ALTER TABLE users
                ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            """)
            conn.commit()
            print("Added 'created_at' column to users table.")
        except psycopg2.Error as e:
            print(f"Error adding column: {e}")
            conn.rollback()
        finally:
            conn.close()
    else:
        print("'created_at' column already exists in users table.")
        conn.close()

else:
    print("Not a PostgreSQL database, skipping migration.")