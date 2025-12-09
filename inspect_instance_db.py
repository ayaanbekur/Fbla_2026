import sqlite3
import json
conn = sqlite3.connect('instance/site.db')
c = conn.cursor()
c.execute("SELECT name, sql FROM sqlite_master WHERE type='table';")
rows = c.fetchall()
print(json.dumps(rows, indent=2, default=str))
conn.close()
