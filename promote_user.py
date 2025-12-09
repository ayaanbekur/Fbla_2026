"""
promote_user.py

Run from project root in the same venv as your app.
Usage (PowerShell):
  python promote_user.py user@example.com

This script loads the Flask app context and sets the `is_admin` flag on the
User with the provided email. It prints the result.
"""
import sys
from init_db import db, User
from app import app

if len(sys.argv) < 2:
    print("Usage: python promote_user.py user@example.com")
    sys.exit(1)

email = sys.argv[1].strip()

with app.app_context():
    user = User.query.filter_by(email=email).first()
    if not user:
        print(f"No user found with email: {email}")
        sys.exit(2)

    if getattr(user, 'is_admin', False):
        print(f"User {email} is already an admin.")
        sys.exit(0)

    user.is_admin = True
    db.session.add(user)
    db.session.commit()
    print(f"User {email} has been promoted to admin.")
