import sqlite3

DB = 'lost_and_found.db'
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
c = conn.cursor()

try:
    rows = c.execute('SELECT id, name, image, description, location, status FROM items').fetchall()
    if not rows:
        print('No items found in lost_and_found.db (items table empty).')
    else:
        for r in rows:
            print(dict(r))
except Exception as e:
    print('Error reading items table:', e)

conn.close()
