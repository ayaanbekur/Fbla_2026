# Standard library
import os
from functools import wraps
from datetime import datetime

# Third-party libraries
import requests
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, jsonify
)
from flask_login import (
    LoginManager, login_user, logout_user, current_user, login_required
)
from werkzeug.utils import secure_filename

# Local modules / database models
from init_db import db, User, Item, Message, AIChat, Report, ClaimRequest

# Load environment variables
load_dotenv()
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")
AI_ENDPOINT = os.getenv("AI_ENDPOINT")
AI_MODEL = os.getenv("AI_MODEL", "openai/gpt-oss-20b:groq")
AI_KEY = os.getenv("AI_API_KEY")

print(f"[STARTUP] ADMIN_USERNAME loaded as: '{ADMIN_USERNAME}'")
print(f"[STARTUP] ADMIN_PASSWORD loaded as: '{ADMIN_PASSWORD}'")

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Uploads
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Database setup
db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if db_url.startswith("postgresql://"):
    db_url += "?sslmode=require"
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# -------------------
# Decorators
# -------------------

def admin_required(f):
    """Decorator to ensure user is logged in and is admin."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

# -------------------
# Flask-Login user loader
# -------------------

# -------------------
# Helper functions
# -------------------

def get_or_create_admin():
    """Return the admin user, creating one if it doesn't exist."""
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        admin = User(name="Admin", email="admin@lost-found.local", is_admin=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
    return admin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------
# Jinja template context
# -------------------

@app.context_processor
def inject_now():
    """Inject helper values into Jinja templates."""
    return {"now": datetime.now, "current_year": datetime.now().year}

with app.app_context():
    db.create_all()

# Home
@app.route("/")
def index():
    return render_template("index.html")
 
# Browse items
@app.route("/browse")
def browse():
    items = Item.query.filter_by(approved=True).all()
    return render_template("browse.html", items=items)


# AI Chat page (display)
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

    # Fetch approved items so Alex can reference them
    items = Item.query.filter_by(approved=True).all()

    # Build item listing for the system prompt
    if items:
        items_list = "Here are the currently available items that users can browse:\n\n"
        for item in items:
            items_list += f"- **{item.name}** (ID: {item.id}): {item.description}\n"
            if item.location:
                items_list += f"  Location: {item.location}\n"
            items_list += f"  Status: {item.status}\n\n"
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
            {"role": "user", "content": user_msg}
        ]
    }

    headers = {"Content-Type": "application/json"}
    if AI_KEY:
        headers["Authorization"] = f"Bearer {AI_KEY}"

    try:
        r = requests.post(AI_ENDPOINT, json=payload, headers=headers, timeout=30)
    except Exception as e:
        print(f"[AI DEBUG] Request to {AI_ENDPOINT} failed: {e}")
        return jsonify({"error": "AI request failed", "detail": str(e)}), 502

    # At this point we have a response object `r` (may be non-2xx)
    try:
        r.raise_for_status()
    except Exception as he:
        # Print response body for debugging
        resp_text = None
        try:
            resp_text = r.text
        except Exception:
            resp_text = '<unreadable body>'
        print(f"[AI DEBUG] Provider returned HTTP {r.status_code}: {resp_text}")
        return jsonify({"error": "AI provider error", "status_code": r.status_code, "detail": resp_text}), 502

    # Try to parse JSON
    try:
        data = r.json()
    except Exception as je:
        print(f"[AI DEBUG] Failed to parse JSON from provider response: {je}\nRaw body: {r.text}")
        return jsonify({"error": "AI response not JSON", "detail": r.text}), 502

    # Parse common response shapes (OpenAI-like and HF router compatible)
    reply = None
    if isinstance(data, dict):
        choices = data.get("choices") or []
        if choices and isinstance(choices, list):
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message")
                if isinstance(msg, dict) and msg.get("content"):
                    reply = msg.get("content")
                elif first.get("text"):
                    reply = first.get("text")
        if not reply:
            reply = data.get("reply") or data.get("output") or data.get("response")

        db.session.add(AIChat(
        user_id=current_user.id,
        sender="user",
        message=user_msg
        ))
        db.session.add(AIChat(
            user_id=current_user.id,
            sender="ai",
            message=reply
        ))
        db.session.commit()


    if not reply:
        try:
            reply = str(data)
        except Exception:
            reply = None

    if not reply:
        print(f"[AI DEBUG] Could not extract reply from provider JSON: {data}")
        return jsonify({"error": "AI response parsing failed", "detail": data}), 502

    print(f"[AI DEBUG] Successfully got reply from {AI_ENDPOINT}")
    return jsonify({"reply": reply})

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
            # If the user record has is_admin=True, set session admin flag so UI shows admin tools
            try:
                if getattr(user, 'is_admin', False):
                    session['admin'] = True
            except Exception:
                pass
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

@app.route("/admin_login", methods=["GET", "POST"])
@admin_required
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and user.check_password(password):
            login_user(user)
            session["admin"] = True
            session["show_admin_popup"] = True
            flash("Welcome to Admin Dashboard!", "success")
            return redirect(url_for("admin"))

        flash("Invalid admin credentials.", "danger")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")

  
# Global chatroom (for navbar link)
# Global chat (everyone)
@app.route("/chat/global", methods=["GET", "POST"])
@login_required
def global_chat():
    if request.method == "POST":
        content = request.form["content"]
        msg = Message(sender_id=current_user.id, receiver_id=None, content=content)  # receiver_id=None = global
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("global_chat"))

    all_messages = Message.query.filter_by(receiver_id=None).order_by(Message.timestamp.asc()).all()
    
    # Format messages with sender names
    messages = []
    for m in all_messages:
        sender_name = "Unknown"
        try:
            if m.sender_id:
                sender = User.query.get(m.sender_id)
                sender_name = sender.name if sender else "Unknown"
        except:
            pass
        messages.append({
            "content": m.content,
            "timestamp": m.timestamp,
            "sender_name": sender_name,
            "is_self": m.sender_id == current_user.id
        })
    
    return render_template("chat.html", messages=messages, chat_type="Global")
 
# Chat with admin
@app.route("/chat/admin", methods=["GET", "POST"])
@admin_required
@login_required
def admin_chat():
    # Check if current user is logged in admin (session-based)
    if session.get("admin"):
        # Admin view: Show all conversations
        return admin_chat_manage()
    
    # Regular user chat with admin
    admin = get_or_create_admin()
    admin_id = admin.id
    if request.method == "POST":
        content = request.form["content"]
        msg = Message(sender_id=current_user.id, receiver_id=admin_id, content=content)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("admin_chat"))

    convo = Message.query.filter(
        (
            (Message.sender_id == current_user.id) & (Message.receiver_id == admin_id)
        ) | (
            (Message.sender_id == admin_id) & (Message.receiver_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    messages = []
    for m in convo:
        sender_name = "Unknown"
        try:
            if m.sender_id:
                sender = User.query.get(m.sender_id)
                sender_name = sender.name if sender else "Unknown"
        except:
            pass
        messages.append({
            "content": m.content,
            "timestamp": m.timestamp,
            "sender_name": sender_name,
            "is_self": m.sender_id == current_user.id
        })

    return render_template("chat.html", messages=messages, chat_type="Admin")


def admin_chat_manage():
    """Admin view of all user conversations with admin"""
    admin = get_or_create_admin()
    admin_id = admin.id


    
    # Get all conversations (unique users who messaged admin)
    conversations = Message.query.filter(
        ((Message.receiver_id == admin_id) | (Message.sender_id == admin_id))
    ).with_entities(Message.sender_id).distinct().all()
    
    user_ids = [c[0] for c in conversations if c[0] != admin_id]
    
    # Get user details and latest message for each conversation
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
    
    # Sort by latest message timestamp
    user_chats.sort(key=lambda x: x["last_timestamp"] or "", reverse=True)
    
    return render_template("admin_chat_manage.html", user_chats=user_chats)


# Admin view specific user conversation
@app.route("/admin/chat/<int:user_id>", methods=["GET", "POST"])
@admin_required
def admin_view_chat(user_id):
    
    admin = get_or_create_admin()
    admin_id = admin.id

    user = User.query.get(user_id)
    
    if not user:
        return "User not found", 404
    
    if request.method == "POST":
        content = request.form["content"]
        msg = Message(sender_id=admin_id, receiver_id=user_id, content=content)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("admin_view_chat", user_id=user_id))
    
    convo = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == admin_id)) |
        ((Message.sender_id == admin_id) & (Message.receiver_id == user_id))
    ).order_by(Message.timestamp.asc()).all()
    
    messages = []
    for m in convo:
        sender_name = "Unknown"
        try:
            if m.sender_id:
                sender = User.query.get(m.sender_id)
                sender_name = sender.name if sender else "Unknown"
        except:
            pass
        messages.append({
            "content": m.content,
            "timestamp": m.timestamp,
            "sender_name": sender_name,
            "is_self": m.sender_id == admin_id
        })
    
    return render_template("admin_chat_view.html", messages=messages, user=user)

# Report lost item
@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        item = Item(
            name=request.form["name"],
            description=request.form["description"],
            location=request.form.get("location"),
            status=request.form["status"],
            owner_id=current_user.id,
            approved=False
        )
        db.session.add(item)
        db.session.commit()
        flash("Item reported. Awaiting admin approval.", "success")
        return redirect(url_for("browse"))

    return render_template("report.html")

# Claim item
@app.route("/claim/<int:item_id>", methods=["GET", "POST"])
def claim(item_id):
    item = Item.query.get(item_id)
    if not item:
        flash("Item not found", "danger")
        return redirect(url_for("browse"))
    return render_template("claim.html", item=item)


# Admin dashboard
# Admin dashboard
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():

    # Handle adding a new item from admin
    if request.method == "POST" and "add_item" in request.form:
        name = request.form["name"]
        description = request.form["description"]
        location = request.form.get("location", "")
        item = Item(name=name, description=description, location=location, status='Found', approved=True)
        db.session.add(item)
        db.session.commit()
        session['admin_action_msg'] = 'Item added'

    items = Item.query.all()

    show_popup = session.pop("show_admin_popup", False)
    action_msg = session.pop('admin_action_msg', None)

    return render_template("admin.html", items=items, show_admin_login_popup=show_popup, admin_action_msg=action_msg)


# Logout
@app.route('/admin/logout', methods=['POST', 'GET'])
@admin_required
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('index'))


# Delete item (POST)
# Admin: delete item
@app.route("/admin/delete/<int:item_id>", methods=['POST'])
@admin_required
def admin_delete(item_id):
    item = Item.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        session['admin_action_msg'] = 'Item deleted'
    return redirect(url_for("admin"))


# Admin: approve item
@app.route("/admin/approve/<int:item_id>", methods=['POST'])
@admin_required
def approve(item_id):
    item = Item.query.get(item_id)
    if item:
        item.approved = True
        db.session.commit()
    return redirect(url_for("admin"))


# Admin: reject item
@app.route("/admin/reject/<int:item_id>", methods=['POST'])
@admin_required
def reject(item_id):
    item = Item.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        session['admin_action_msg'] = 'Item rejected and removed'
    return redirect(url_for("admin"))


# Admin: clear claim
@app.route("/admin/clear_claim/<int:item_id>", methods=['POST'])
@admin_required
def clear_claim(item_id):
    item = Item.query.get(item_id)
    if item:
        item.status = 'Found'
        item.claimant = None
        db.session.commit()
        session['admin_action_msg'] = 'Claim cleared'
    return redirect(url_for("admin"))


# Admin: remove item
@app.route("/admin/remove/<int:item_id>", methods=['POST'])
@admin_required
def remove_item(item_id):
    item = Item.query.get(item_id)
    if item:
        item.status = 'Removed'
        item.claimant = None
        db.session.commit()
        session['admin_action_msg'] = 'Item marked Removed'
    return redirect(url_for("admin"))


# Admin: delete item from browse view
@app.route("/admin/delete_from_browse/<int:item_id>", methods=['POST'])
@admin_required
def admin_delete_browse(item_id):
    item = Item.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        session['admin_action_msg'] = 'Item deleted'
    return redirect(url_for("browse"))


# Admin: mark item as claimed
@app.route("/admin/mark_claimed/<int:item_id>", methods=['POST'])
@admin_required
def admin_mark_claimed(item_id):
    item = Item.query.get(item_id)
    if item:
        item.status = 'Claimed'
        item.claimant = 'Admin'
        db.session.commit()
        session['admin_action_msg'] = 'Item marked Claimed'
    return redirect(url_for("browse"))


# Admin: approve claim request
@app.route("/admin/approve_claim/<int:claim_id>", methods=['POST'])
@admin_required
def admin_approve_claim(claim_id):
    claim = ClaimRequest.query.get(claim_id)
    if claim:
        claim.status = 'approved'
        db.session.commit()
        session['admin_action_msg'] = f'Claim request from {claim.claimant_name} approved'
    return redirect(url_for("admin"))


# Admin: reject claim request
@app.route("/admin/reject_claim/<int:claim_id>", methods=['POST'])
@admin_required
def admin_reject_claim(claim_id):
    claim = ClaimRequest.query.get(claim_id)
    if claim:
        claim.status = 'rejected'
        db.session.commit()
        session['admin_action_msg'] = f'Claim request from {claim.claimant_name} rejected'
    return redirect(url_for("admin"))


# Admin: get list of users to chat with
@app.route("/admin/chat_users", methods=['GET'])
@admin_required
def admin_chat_users():
    
    users = User.query.all()
    return render_template("admin_chat_users.html", users=users)


# Admin: start chat with a specific user
@app.route("/admin/chat_with/<int:user_id>", methods=['GET'])
@admin_required
def admin_chat_with(user_id):
    
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("admin_chat_users"))
    
    # Fetch chat history
    admin = get_or_create_admin()
    admin_id = admin.id

    messages = db.session.query(Message).filter(
        ((Message.sender_id == admin_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == admin_id))
    ).order_by(Message.timestamp).all()
    
    return render_template("admin_chat_with_user.html", user=user, messages=messages)


# Admin: send message to user
@app.route("/admin/send_to_user/<int:user_id>", methods=['POST'])
@admin_required
def admin_send_to_user(user_id):
    
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("admin_chat_users"))
    
    # Accept either 'content' (used in templates) or 'message' (older name) from the form
    content = (request.form.get("content") or request.form.get("message") or "").strip()
    if content:
        admin = get_or_create_admin()
        admin_id = admin.id
        msg = Message(sender_id=admin_id, receiver_id=user_id, content=content)  # ✅ create message object
        db.session.add(msg)  # ✅ add the correct object
        db.session.commit()
    
    return redirect(url_for("admin_chat_with", user_id=user_id))


# Run
if __name__ == "__main__":
    app.run(debug=True)