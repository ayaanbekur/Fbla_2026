from init_db import db
from app import app  # import your Flask app instance

with app.app_context():
    db.create_all()
    print("Tables created successfully!")
