from app import app
from init_db import db, User

with app.app_context():
    admin = User.query.filter_by(email="ayaanbekur@gmail.com").first()
    if not admin:
        admin = User(name="Admin", email="ayaanbekur@gmail.com", is_admin=True)
        admin.set_password("strongpassword123")  # choose a secure one
        db.session.add(admin)
        db.session.commit()
    print("✅ Admin created or already exists!")
