"""
check_user_in_dbs.py

Usage:
  python check_user_in_dbs.py user@example.com [password]

Scans common DB files in the project for a `user` table and prints matches.
If a password is provided it will verify the hash using werkzeug.check_password_hash.
"""
import sys
import sqlite3
import os
from werkzeug.security import check_password_hash

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_FILES = [
    os.path.join(PROJECT_ROOT, 'site.db'),
    os.path.join(PROJECT_ROOT, 'instance', 'site.db'),
    os.path.join(PROJECT_ROOT, 'database.db'),
    os.path.join(PROJECT_ROOT, 'lost_and_found.db'),
]

email_to_find = sys.argv[1] if len(sys.argv) > 1 else None
password_to_test = sys.argv[2] if len(sys.argv) > 2 else None

found_any = False
for db_path in DB_FILES:
    if not os.path.exists(db_path):
        continue
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        # find possible user table names
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        user_tables = [t for t in tables if t.lower() in ('user', 'users')]
        if not user_tables:
            conn.close()
            continue

        for ut in user_tables:
            query = f"SELECT id, name, email, password_hash, is_admin FROM {ut}"
            try:
                cur.execute(query)
            except Exception:
                # maybe columns differ; try select without is_admin
                try:
                    cur.execute(f"SELECT id, name, email, password_hash FROM {ut}")
                    rows = cur.fetchall()
                    rows = [r + (None,) for r in rows]
                except Exception:
                    continue
            else:
                rows = cur.fetchall()

            if not rows:
                continue

            print(f"\nDB File: {db_path} (table: {ut})")
            for r in rows:
                uid, name, email, pwhash, is_admin = r[0], r[1], r[2], r[3], (r[4] if len(r) > 4 else None)
                print(f"  id={uid} name={name!r} email={email!r} is_admin={is_admin}")
                if email_to_find and email.lower() == email_to_find.lower():
                    found_any = True
                    print("    --> Found target email in this DB.")
                    if password_to_test:
                        try:
                            ok = check_password_hash(pwhash, password_to_test)
                            print(f"    Password match: {ok}")
                        except Exception as e:
                            print(f"    Could not verify password: {e}")
        conn.close()
    except Exception as e:
        print(f"Could not read {db_path}: {e}")

if email_to_find and not found_any:
    print(f"\nUser {email_to_find} not found in scanned DBs.")

print("\nScan complete.")
