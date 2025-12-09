import sqlite3

DB = 'instance/site.db'

conn = sqlite3.connect(DB)
cursor = conn.cursor()

# Check if column exists
cursor.execute("PRAGMA table_info(user);")
cols = [r[1] for r in cursor.fetchall()]
print('Current columns in user table:', cols)

if 'is_admin' in cols:
    print("'is_admin' column already exists in user table.")
else:
    try:
        cursor.execute("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0;")
        conn.commit()
        print("Added 'is_admin' column to user table.")
    except sqlite3.OperationalError as e:
        print('Failed to add column:', e)

conn.close()
