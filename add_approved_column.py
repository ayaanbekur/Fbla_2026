import sqlite3

conn = sqlite3.connect("site.db")
cursor = conn.cursor()

# List all tables to check the actual table name
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [t[0] for t in cursor.fetchall()]
print("Tables in DB:", tables)

# Replace 'items' below with whatever table you actually have
table_name = 'items'

# Check columns
cursor.execute(f"PRAGMA table_info({table_name})")
columns = [col[1] for col in cursor.fetchall()]
print("Columns in table:", columns)

# Add 'approved' column if it doesn't exist
if "approved" not in columns:
    cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN approved BOOLEAN DEFAULT 0")
    print(f"Column 'approved' added to {table_name}!")
else:
    print(f"Column 'approved' already exists in {table_name}.")

conn.commit()
conn.close()
