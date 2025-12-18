import sqlite3

conn = sqlite3.connect("site.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    location TEXT,
    status TEXT DEFAULT 'Found',
    approved BOOLEAN DEFAULT 0,
    image_filename TEXT,
    owner_id INTEGER
)
""")

conn.commit()
conn.close()
print("Table 'items' created (if it didn't exist).")
