from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid

# Initialize SQLAlchemy here, not in app.py
db = SQLAlchemy()

# --------------------------
# USER MODEL
# --------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    school = db.Column(db.String(50), nullable=False)  # Forsyth County high schools
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sent_messages = db.relationship("Message", foreign_keys="Message.sender_id", backref="sender_user", lazy=True)
    received_messages = db.relationship("Message", foreign_keys="Message.receiver_id", backref="receiver_user", lazy=True)
    items = db.relationship("Item", backref="owner", lazy=True)
    ai_chats = db.relationship("AIChat", backref="user", lazy=True)
    reports = db.relationship("Report", backref="reporter", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# --------------------------
# ITEM MODEL
# --------------------------
class Item(db.Model):
    __tablename__ = "item"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    school = db.Column(db.String(50), nullable=False)  # Forsyth County high schools
    status = db.Column(db.String(50), default='Found')
    approved = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    guest_email = db.Column(db.String(120), nullable=True)  # Email for guest posters
    claimant = db.Column(db.String(100))
    secret_detail = db.Column(db.Text, nullable=True)  # The detail owner hides (e.g., engraving, lock screen photo)
    
    # Smart Search & Filters
    category = db.Column(db.String(50), nullable=True)  # electronics, clothes, jewelry, books, etc.
    color = db.Column(db.String(50), nullable=True)  # For filtering by color
    brand = db.Column(db.String(100), nullable=True)  # Brand name
    date_lost = db.Column(db.Date, nullable=True)  # When item was lost (for date slider)
    date_found = db.Column(db.Date, default=datetime.utcnow)  # When item was found
    
    # Auto-Archive & Donation
    claim_deadline = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))
    is_archived = db.Column(db.Boolean, default=False)
    archive_date = db.Column(db.DateTime, nullable=True)
    
    # QR Code for pickup
    qr_code = db.Column(db.String(100), unique=True, nullable=True)  # Unique QR code identifier


# --------------------------
# MESSAGE MODEL
# --------------------------
class Message(db.Model):
    __tablename__ = "message"
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# AI CHAT MODEL
# --------------------------
class AIChat(db.Model):
    __tablename__ = "ai_chat"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    sender = db.Column(db.String(10))
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# REPORT MODEL
# --------------------------
class Report(db.Model):
    __tablename__ = "report"
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"))
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="pending")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# CLAIM REQUEST MODEL
# --------------------------
class ClaimRequest(db.Model):
    __tablename__ = "claim_request"
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"))
    claimant_name = db.Column(db.String(100))
    claimant_email = db.Column(db.String(120), nullable=True)  # Email for guest claimants
    status = db.Column(db.String(20), default="pending")
    claim_reason = db.Column(db.Text, nullable=True)  # Why they think it's theirs
    identifiable_features = db.Column(db.Text, nullable=True)  # Features that prove ownership
    secret_detail_answer = db.Column(db.Text, nullable=True)  # Their answer to the secret detail
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    staff_approved = db.Column(db.Boolean, default=False)  # Staff verification
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # Which admin approved it
    approved_at = db.Column(db.DateTime, nullable=True)  # When it was approved
    pickup_qr_verified = db.Column(db.Boolean, default=False)  # QR code scanned at pickup




