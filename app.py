import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)
from flask_login import (
    LoginManager, login_user, logout_user,
    current_user, login_required
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import requests

from init_db import db, User, Item, Message, ClaimRequest

# Load environment variables
load_dotenv()

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")

print(f"[STARTUP] ADMIN_USERNAME loaded as: '{ADMIN_USERNAME}'")
print(f"[STARTUP] ADMIN_PASSWORD loaded as: '{ADMIN_PASSWORD}'")

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File upload folder
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize database
db.init_app(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------------------------------------
# Context processors
# ---------------------------------------------
@app.context_processor
def inject_now():
    return {"now": datetime.now, "current_year": datetime.now().year}


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------
# Routes: Home & DB
# ---------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/init-db")
def init_db():
    db.create_all()
    return "Database created successfully"


# ---------------------------------------------
# Browse items
# ---------------------------------------------
@app.route("/browse")
def browse():
    items = Item.query.filter_by(approved=True).all()
    return render_template("browse.html", items=items)


# ---------------------------------------------
# AI Chat
# ---------------------------------------------
AI_ENDPOINT = os.getenv("AI_ENDPOINT")
AI_MODEL = os.getenv("AI_MODEL", "openai/gpt-oss-20b:groq")
AI_KEY = os.getenv("AI_API_KEY")


@app.route("/chat/ai")
@login_required
def ai_chat_page():
    return render_template("ai_chat.html")


@app.route("/ai_chat", methods=["POST"])
@login_required
def ai_chat():
    data = request.get_json() or {}
    user_msg = data.get("message", "").strip()

    if not user_msg:
        return jsonify({"error": "empty message"}), 400
    if not AI_ENDPOINT:
        return jsonify({"error": "AI_ENDPOINT not configured"}), 500

    # Fetch approved items
    items = Item.query.filter_by(approved=True).all()

    # Build item listing
    if items:
        items_list = "Here are the currently available items that users can browse:\n\n"
        for item in items:
            items_list += (
                f"- **{item.name}** (ID: {item.id}): {item.description}\n"
                f"  Location: {item.location}, Status: {item.status}\n"
            )
    else:
        items_list = "There are currently no approved items available."

    system_prompt = f"""You are Alex, a friendly AI assistant for a Lost & Found service. Your job is to help users find items they're looking for.

{items_list}

When users ask about items, reference what's available or help them report a lost item. Be helpful, concise, and warm.

**FORMATTING FREEDOM:** You can format your replies however you want using:
- **Bold** and *italics* for emphasis
- Emojis 🎉 📦 🔍 ❓ 💡 to make responses more engaging
- Bullet points and numbered lists for clarity
- Line breaks and spacing for readability
- Headers and sections to organize information

Use your creativity to make responses clear, helpful, and friendly!"""

    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
    }

    headers = {"Content-Type": "application/json"}
    if AI_KEY:
        headers["Authorization"] = f"Bearer {AI_KEY}"

    try:
        r = requests.post(AI_ENDPOINT, json=payload, headers=headers, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"[AI DEBUG] Request failed: {e}")
        return jsonify({"error": "AI request failed", "detail": str(e)}), 502

    try:
        data = r.json()
    except Exception as je:
        print(f"[AI DEBUG] JSON parse error: {je}")
        return jsonify({"error": "AI response not JSON", "detail": r.text}), 502

    reply = None
    if isinstance(data, dict):
        choices = data.get("choices") or []
        if choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message")
                if isinstance(msg, dict) and msg.get("content"):
                    reply = msg.get("content")
                elif first.get("text"):
                    reply = first.get("text")
        if not reply:
            reply = data.get("reply") or data.get("output") or data.get("response")

    if not reply:
        reply = str(data)

    return jsonify({"reply": reply})


# ---------------------------------------------
# Authentication
# ---------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))

        new_user = User(name=name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            if getattr(user, "is_admin", False):
                session["admin"] = True
            flash("Logged in successfully!", "success")
            return redirect(url_for("index"))

        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))


# ---------------------------------------------
# Admin login
# ---------------------------------------------
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            session["show_admin_popup"] = True
            flash("Welcome to Admin Dashboard!", "success")
            return redirect(url_for("admin"))
        else:
            flash("Invalid admin credentials.", "danger")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


# ---------------------------------------------
# Global chat
# ---------------------------------------------
@app.route("/chat/global", methods=["GET", "POST"])
@login_required
def global_chat():
    if request.method == "POST":
        content = request.form["content"]
        msg = Message(sender_id=current_user.id, receiver_id=None, content=content)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("global_chat"))

    all_messages = Message.query.filter_by(receiver_id=None).order_by(Message.timestamp.asc()).all()

    messages = []
    for m in all_messages:
        sender_name = "Unknown"
        if m.sender_id:
            sender = User.query.get(m.sender_id)
            sender_name = sender.name if sender else "Unknown"
        messages.append({
            "content": m.content,
            "timestamp": m.timestamp,
            "sender_name": sender_name,
            "is_self": m.sender_id == current_user.id
        })

    return render_template("chat.html", messages=messages, chat_type="Global")


# ---------------------------------------------
# Chat with admin
# ---------------------------------------------
@app.route("/chat/admin", methods=["GET", "POST"])
@login_required
def admin_chat():
    if session.get("admin"):
        return admin_chat_manage()

    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(name="Admin", email="admin@lost-found.local", is_admin=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()

    admin_id = admin.id

    if request.method == "POST":
        content = request.form["content"]
        msg = Message(sender_id=current_user.id, receiver_id=admin_id, content=content)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("admin_chat"))

    convo = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == admin_id)) |
        ((Message.sender_id == admin_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    messages = []
    for m in convo:
        sender_name = "Unknown"
        if m.sender_id:
            sender = User.query.get(m.sender_id)
            sender_name = sender.name if sender else "Unknown"
        messages.append({
            "content": m.content,
            "timestamp": m.timestamp,
            "sender_name": sender_name,
            "is_self": m.sender_id == current_user.id
        })

    return render_template("chat.html", messages=messages, chat_type="Admin")


def admin_chat_manage():
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(name="Admin", email="admin@lost-found.local", is_admin=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()

    admin_id = admin.id

    conversations = Message.query.filter(
        (Message.receiver_id == admin_id) | (Message.sender_id == admin_id)
    ).with_entities(Message.sender_id).distinct().all()

    user_ids = [c[0] for c in conversations if c[0] != admin_id]

    user_chats = []
    for user_id in user_ids:
        user = User.query.get(user_id)
        if user:
            last_msg = Message.query.filter(
                ((Message.sender_id == user_id) & (Message.receiver_id == admin_id)) |
                ((Message.sender_id == admin_id) & (Message.receiver_id == user_id))
            ).order_by(Message.timestamp.desc()).first()

            user_chats.append({
                "user_id": user_id,
                "user_name": user.name,
                "user_email": user.email,
                "last_message": last_msg.content if last_msg else "No messages",
                "last_timestamp": last_msg.timestamp if last_msg else None
            })

    user_chats.sort(key=lambda x: x["last_timestamp"] or "", reverse=True)
    return render_template("admin_chat_manage.html", user_chats=user_chats)
# ---------------------------------------------
# Admin view specific user conversation
# ---------------------------------------------
@app.route("/admin/chat/<int:user_id>", methods=["GET", "POST"])
def admin_view_chat(user_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(name="Admin", email="admin@lost-found.local", is_admin=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()

    user = User.query.get_or_404(user_id)
    admin_id = admin.id

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content:
            msg = Message(sender_id=admin_id, receiver_id=user.id, content=content)
            db.session.add(msg)
            db.session.commit()
        return redirect(url_for("admin_view_chat", user_id=user_id))

    convo = Message.query.filter(
        ((Message.sender_id == user.id) & (Message.receiver_id == admin_id)) |
        ((Message.sender_id == admin_id) & (Message.receiver_id == user.id))
    ).order_by(Message.timestamp.asc()).all()

    messages = []
    for m in convo:
        sender_name = "Unknown"
        if m.sender_id:
            sender = User.query.get(m.sender_id)
            sender_name = sender.name if sender else "Unknown"
        messages.append({
            "content": m.content,
            "timestamp": m.timestamp,
            "sender_name": sender_name,
            "is_self": m.sender_id == admin_id
        })

    return render_template("admin_chat_view.html", messages=messages, user=user)


# ---------------------------------------------
# Report lost/found item
# ---------------------------------------------
@app.route("/report", methods=["GET", "POST"])
def report():
    success_msg = None
    if request.method == "POST":
        name = request.form.get("name")
        location = request.form.get("location", "")
        description = request.form.get("description")
        status = request.form.get("status")
        image = request.files.get("image")

        filename = None
        if image and image.filename:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        new_item = Item(
            name=name,
            location=location,
            description=description,
            status=status,
            image=filename,
            approved=False
        )
        db.session.add(new_item)
        db.session.commit()

        success_msg = "Item reported successfully!"
        return render_template("report.html", success_msg=success_msg)

    return render_template("report.html")


# ---------------------------------------------
# Claim an item
# ---------------------------------------------
@app.route("/claim/<int:item_id>", methods=["GET", "POST"])
def claim(item_id):
    item = Item.query.get_or_404(item_id)
    if request.method == "POST":
        claimant = request.form.get("claimant", "Unknown")
        item.status = "Claimed"
        item.claimant = claimant
        db.session.commit()
        return redirect(url_for("browse"))
    return render_template("claim.html", item=item)


# ---------------------------------------------
# Admin dashboard
# ---------------------------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    if request.method == "POST" and "add_item" in request.form:
        name = request.form.get("name")
        description = request.form.get("description")
        location = request.form.get("location", "")
        new_item = Item(
            name=name,
            description=description,
            location=location,
            status="Found",
            approved=True
        )
        db.session.add(new_item)
        db.session.commit()

    items = Item.query.all()

    show_popup = session.pop("show_admin_popup", False)
    action_msg = session.pop("admin_action_msg", None)

    return render_template(
        "admin.html",
        items=items,
        show_admin_login_popup=show_popup,
        admin_action_msg=action_msg
    )


# ---------------------------------------------
# Admin logout
# ---------------------------------------------
@app.route("/admin/logout", methods=["GET", "POST"])
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("index"))


# ---------------------------------------------
# Admin item actions
# ---------------------------------------------
def require_admin():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))


@app.route("/admin/delete/<int:item_id>", methods=["POST"])
def admin_delete(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    session["admin_action_msg"] = "Item deleted"
    return redirect(url_for("admin"))


@app.route("/admin/approve/<int:item_id>", methods=["POST"])
def approve(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    item.approved = True
    db.session.commit()
    return redirect(url_for("admin"))


@app.route("/admin/reject/<int:item_id>", methods=["POST"])
def reject(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    session["admin_action_msg"] = "Item rejected and removed"
    return redirect(url_for("admin"))


@app.route("/admin/clear_claim/<int:item_id>", methods=["POST"])
def clear_claim(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    item.status = "Found"
    item.claimant = None
    db.session.commit()
    session["admin_action_msg"] = "Claim cleared"
    return redirect(url_for("admin"))


@app.route("/admin/remove/<int:item_id>", methods=["POST"])
def remove_item(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    item.status = "Removed"
    item.claimant = None
    db.session.commit()
    session["admin_action_msg"] = "Item marked Removed"
    return redirect(url_for("admin"))


@app.route("/admin/delete_from_browse/<int:item_id>", methods=["POST"])
def admin_delete_browse(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    session["admin_action_msg"] = "Item deleted"
    return redirect(url_for("browse"))


@app.route("/admin/mark_claimed/<int:item_id>", methods=["POST"])
def admin_mark_claimed(item_id):
    require_admin()
    item = Item.query.get_or_404(item_id)
    item.status = "Claimed"
    item.claimant = "Admin"
    db.session.commit()
    session["admin_action_msg"] = "Item marked Claimed"
    return redirect(url_for("browse"))


# ---------------------------------------------
# Admin approve/reject claim requests
# ---------------------------------------------
@app.route("/admin/approve_claim/<int:claim_id>", methods=["POST"])
def admin_approve_claim(claim_id):
    require_admin()
    claim = ClaimRequest.query.get_or_404(claim_id)
    claim.status = "approved"
    db.session.commit()
    session["admin_action_msg"] = f"Claim request from {claim.claimant_name} approved"
    return redirect(url_for("admin"))


@app.route("/admin/reject_claim/<int:claim_id>", methods=["POST"])
def admin_reject_claim(claim_id):
    require_admin()
    claim = ClaimRequest.query.get_or_404(claim_id)
    claim.status = "rejected"
    db.session.commit()
    session["admin_action_msg"] = f"Claim request from {claim.claimant_name} rejected"
    return redirect(url_for("admin"))


# ---------------------------------------------
# Admin chat user management
# ---------------------------------------------
@app.route("/admin/chat_users", methods=["GET"])
def admin_chat_users():
    require_admin()
    users = User.query.all()
    return render_template("admin_chat_users.html", users=users)


@app.route("/admin/chat_with/<int:user_id>", methods=["GET"])
def admin_chat_with(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)
    admin = User.query.filter_by(is_admin=True).first()
    admin_id = admin.id if admin else 1

    messages = Message.query.filter(
        ((Message.sender_id == admin_id) & (Message.receiver_id == user.id)) |
        ((Message.sender_id == user.id) & (Message.receiver_id == admin_id))
    ).order_by(Message.timestamp.asc()).all()

    return render_template("admin_chat_with_user.html", user=user, messages=messages)


@app.route("/admin/send_to_user/<int:user_id>", methods=["POST"])
def admin_send_to_user(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)
    content = (request.form.get("content") or request.form.get("message") or "").strip()
    if content:
        admin = User.query.filter_by(is_admin=True).first()
        admin_id = admin.id if admin else 1
        message = Message(sender_id=admin_id, receiver_id=user.id, content=content)
        db.session.add(message)
        db.session.commit()
    return redirect(url_for("admin_chat_with", user_id=user.id))
# Run
if __name__ == "__main__":
    app.run(debug=True)
