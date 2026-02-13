import sqlite3
from datetime import datetime

DB = 'instance/site.db'

conn = sqlite3.connect(DB)
cursor = conn.cursor()

# Check if column exists
cursor.execute("PRAGMA table_info(users);")
cols = [r[1] for r in cursor.fetchall()]
print('Current columns in users table:', cols)

if 'created_at' in cols:
    print("'created_at' column already exists in users table.")
else:
    try:
        # First add the column without default
        cursor.execute("ALTER TABLE users ADD COLUMN created_at DATETIME;")
        # Then update existing rows with current timestamp
        cursor.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;")
        conn.commit()
        print("Added 'created_at' column to users table.")
    except sqlite3.OperationalError as e:
        print(f"Error adding column: {e}")
    finally:
        conn.close()