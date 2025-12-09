import sqlite3

conn = sqlite3.connect("database.db")
c = conn.cursor()
try:
    c.execute("ALTER TABLE items ADD COLUMN photo TEXT;")
except sqlite3.OperationalError:
    print("Column 'photo' already exists.")
conn.commit()
conn.close()
