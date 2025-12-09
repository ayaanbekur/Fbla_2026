from app import app
from init_db import db

with app.app_context():
    db.create_all()
    print("Tables created successfully!")
