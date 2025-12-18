from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# --------------------------
# USER MODEL
# --------------------------
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    # relationships
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
# ITEM MODEL (Lost & Found)
# --------------------------
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Found')
    approved = db.Column(db.Boolean, default=False)
    image_filename = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    claimant = db.Column(db.String(100))



# --------------------------
# MESSAGE MODEL (Global/Admin chat)
# --------------------------
class Message(db.Model):
    __tablename__ = "message"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)  # null = global chat
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# AI CHAT MODEL (Per-user)
# --------------------------
class AIChat(db.Model):
    __tablename__ = "ai_chat"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    sender = db.Column(db.String(10))  # user / ai
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# REPORT MODEL (Admin approval)
# --------------------------
class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"))
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / approved / rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
