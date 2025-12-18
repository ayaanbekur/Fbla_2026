import sqlite3
import os

# Full path to the DB file (make sure it's correct)
db_path = os.path.join(os.getcwd(), "site.db")
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Add the column if it doesn't exist
try:
    c.execute("ALTER TABLE item ADD COLUMN approved BOOLEAN DEFAULT 0;")
    print("Column 'approved' added!")
except sqlite3.OperationalError as e:
    print("Error:", e)

conn.commit()
conn.close()
