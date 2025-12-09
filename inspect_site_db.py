import sqlite3
conn = sqlite3.connect('site.db')
c = conn.cursor()
try:
    c.execute("SELECT name, sql FROM sqlite_master WHERE type='table';")
    for r in c.fetchall():
        print(r[0])
        print(r[1])
        print('---')
except Exception as e:
    print('Error:', e)
conn.close()
