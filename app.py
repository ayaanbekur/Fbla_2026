# Standard library
import os
from functools import wraps
from datetime import datetime
import json

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

print("[STARTUP] Starting Flask application...")

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
print("[STARTUP] Flask app created")

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
print("[STARTUP] Flask-Login initialized")

# Uploads
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
print("[STARTUP] Upload folder configured")

# Database setup
db_url = os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(os.getcwd(), "site.db")}')
print(f"[STARTUP] Database URL: {db_url[:50]}...")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
    if "sslmode" not in db_url:
        db_url += "?sslmode=require"
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
print("[STARTUP] Database configured")

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
    admin = User.query.filter_by(email=ADMIN_USERNAME).first()

    if not admin:
        admin = User(
            name="Admin",
            email=ADMIN_USERNAME,
            is_admin=True,
            school="All Schools"  # Admin can see all schools
        )
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
    else:
        # FORCE admin privileges
        admin.is_admin = True
        admin.set_password(ADMIN_PASSWORD)
        # Ensure admin has a school set
        if not admin.school:
            admin.school = "All Schools"

    # Set created_at if not set
    if admin.created_at is None:
        admin.created_at = datetime.utcnow()

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

def run_migration():
    """Run database migrations for production"""
    try:
        print("[MIGRATION] Starting database migration check...")
        # Check if we're using PostgreSQL
        if db_url.startswith("postgresql://"):
            print("[MIGRATION] Detected PostgreSQL database")
            import psycopg2
            import urllib.parse

            # Parse the database URL
            parsed = urllib.parse.urlparse(db_url)
            dbname = parsed.path.lstrip('/')
            user = parsed.username
            password = parsed.password
            host = parsed.hostname
            port = parsed.port or 5432

            print(f"[MIGRATION] Connecting to database: {host}:{port}/{dbname}")
            # Connect to PostgreSQL
            conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port,
                sslmode='require' if 'sslmode=require' in db_url else 'prefer'
            )
            cursor = conn.cursor()

            # Check if created_at column exists
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'created_at'
            """)
            exists = cursor.fetchone()

            if not exists:
                print("[MIGRATION] Adding created_at column to users table...")
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                """)
                conn.commit()
                print("[MIGRATION] Successfully added created_at column.")
            else:
                print("[MIGRATION] created_at column already exists.")

            conn.close()
            print("[MIGRATION] Migration completed successfully")
        else:
            print("[MIGRATION] Not PostgreSQL, skipping migration")
    except Exception as e:
        print(f"[MIGRATION] Migration error: {e}")
        # Don't fail the entire app startup for migration issues
        pass

with app.app_context():
    print("[STARTUP] Creating app context...")
    run_migration()
    print("[STARTUP] Running db.create_all()...")
    db.create_all()
    print("[STARTUP] Database tables created")

    # Run school migration
    print("[STARTUP] Running school migration...")
    try:
        from migrate_add_school import run_school_migration
        run_school_migration()
    except Exception as e:
        print(f"[STARTUP] School migration error: {e}")

    # Update existing users to have created_at timestamps
    print("[STARTUP] Checking for users without created_at...")
    users_without_created_at = User.query.filter(User.created_at.is_(None)).all()
    for user in users_without_created_at:
        user.created_at = datetime.utcnow()
    if users_without_created_at:
        db.session.commit()
        print(f"[STARTUP] Updated {len(users_without_created_at)} users with created_at timestamps.")

    print("[STARTUP] Creating/checking admin user...")
    get_or_create_admin()
    print("[STARTUP] Admin user ready")

print("[STARTUP] Flask app initialization complete!")

# Home
@app.route("/")
def index():
    # Check if user has selected a school
    selected_school = session.get('school')
    if not selected_school:
        return redirect(url_for('select_school'))
    return render_template("index.html", selected_school=selected_school)

# School selection
@app.route("/select-school")
def select_school():
    return render_template("select_school.html")

@app.route("/set-school", methods=['POST'])
def set_school():
    school = request.form.get('school')
    if school:
        session['school'] = school
        session.permanent = True  # Make session persistent
    return redirect(url_for('index'))

# Switch school view
@app.route("/switch_school", methods=["GET", "POST"])
@login_required
def switch_school():
    if request.method == "POST":
        school = request.form.get("school")
        if school:
            session['school'] = school
            flash(f"Now viewing items from {school}", "success")
            return redirect(url_for('browse', school=school))
    
    # Get all available schools
    schools = [
        "South Forsyth", "North Forsyth", "West Forsyth", "East Forsyth",
        "Forsyth Central", "Lambert", "Denmark", "Alliance"
    ]
    
    current_school = session.get('school', 'South Forsyth')
    return render_template("switch_school.html", schools=schools, current_school=current_school)
 
# Browse items
@app.route("/browse")
def browse():
    # Check if user has selected a school
    selected_school = session.get('school')
    if not selected_school:
        return redirect(url_for('select_school'))

    # Allow viewing items from any school (admins see all, users can switch)
    view_school = request.args.get('school', selected_school)

    search_query = request.args.get("q", "").strip()
    items = Item.query.filter_by(approved=True, school=view_school).all()

    if search_query:
        search_query_lower = search_query.lower()
        items = [
            item for item in items
            if search_query_lower in item.name.lower()
            or search_query_lower in item.description.lower()
            or search_query_lower in item.location.lower()
        ]

    return render_template("browse.html", items=items, search_query=search_query, selected_school=selected_school, view_school=view_school)


# Guest: Post a found item (no login required)
@app.route("/post_found_item", methods=["GET", "POST"])
def post_found_item():
    """Allow guests to post found items without creating an account."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        school = request.form.get("school", "South Forsyth")
        secret_detail = request.form.get("secret_detail", "").strip()
        guest_email = request.form.get("email", "").strip()

        # Validate required fields
        if not name or not description or not secret_detail or not guest_email:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for("post_found_item"))

        # Handle image upload
        image_filename = None
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename:
                filename = secure_filename(file.filename)
                # Add timestamp to make unique
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_")
                filename = timestamp + filename
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                image_filename = filename

        # Create item
        new_item = Item(
            name=name,
            description=description,
            location=location,
            school=school,
            status='Found',
            approved=False,  # Requires admin approval
            image_filename=image_filename,
            secret_detail=secret_detail,
            guest_email=guest_email,
            owner_id=None  # Guest post, no user account
        )

        db.session.add(new_item)
        db.session.commit()

        flash(f"Your found item has been posted! We've sent a verification email to {guest_email}. Check your email to confirm your post.", "success")
        return redirect(url_for("browse"))

    schools = [
        "South Forsyth", "North Forsyth", "West Forsyth", "East Forsyth",
        "Forsyth Central", "Lambert", "Denmark", "Alliance"
    ]
    return render_template("post_found_item.html", schools=schools)


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

    # Fetch approved items
    items = Item.query.filter_by(approved=True).all()

    if items:
        items_list = "Here are the currently available items that users can browse:\n\n"
        for item in items:
            items_list += f"- **{item.name}** (ID: {item.id}): {item.description}\n"
            if item.location:
                items_list += f"  Location: {item.location}\n"
            items_list += f"  Status: {item.status}\n\n"
    else:
        items_list = "There are currently no approved items available."

    system_prompt = f"""
You are Roman, a friendly AI assistant for a Lost & Found service.

{items_list}

You may use **bold**, *italics*, emojis, bullet points, spacing, and headers.

If the user says they lost something, enter LOST_ITEM_MODE.

In LOST_ITEM_MODE:
- Ask for item name, description, and last seen location
- When ready, respond ONLY with JSON:

{{
  "action": "create_lost_item",
  "name": "",
  "description": "",
  "location": ""
}}

No extra text outside JSON.
"""

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
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print("[AI ERROR]", e)
        return jsonify({"error": "AI failed"}), 502

    # ---- Extract reply safely ----
    reply = ""

    if isinstance(data, dict):
        choices = data.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            reply = msg.get("content", "")

    reply = reply.strip()

    # ---- LOST_ITEM_MODE handler ----
    try:
        action_data = json.loads(reply)

        if action_data.get("action") == "create_lost_item":
            # Get user's school from session
            user_school = session.get('school', 'South Forsyth')

            new_item = Item(
                name=action_data["name"],
                description=action_data["description"],
                location=action_data["location"],
                school=user_school,
                status="Lost",
                approved=False,
                owner_id=current_user.id
            )
            db.session.add(new_item)
            db.session.commit()

            confirmation = (
                "📦 **Your lost item has been reported!**\n\n"
                "An admin will review it shortly."
            )

            db.session.add(AIChat(
                user_id=current_user.id,
                sender="user",
                message=user_msg
            ))
            db.session.add(AIChat(
                user_id=current_user.id,
                sender="ai",
                message=confirmation
            ))
            db.session.commit()

            return jsonify({"reply": confirmation})

    except json.JSONDecodeError:
        pass  # normal AI message, not JSON

    # ---- Normal AI reply ----
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

    return jsonify({"reply": reply})


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        school = request.form["school"]

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))

        new_user = User(name=name, email=email, school=school)
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

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not current_password or not new_password or not confirm_password:
            flash("All password fields are required.", "danger")
            return redirect(url_for("settings"))

        if not current_user.check_password(current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("settings"))

        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("settings"))

        if len(new_password) < 6:
            flash("New password must be at least 6 characters long.", "danger")
            return redirect(url_for("settings"))

        current_user.set_password(new_password)
        db.session.commit()
        flash("Password changed successfully!", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html")

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
        # Get user's school from session
        user_school = session.get('school', 'South Forsyth')
        
        item = Item(
            name=request.form["name"],
            description=request.form["description"],
            location=request.form.get("location"),
            status=request.form["status"],
            school=user_school,
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
    
    if request.method == "POST":
        claimant_name = request.form.get("claimant_name", "").strip()
        claimant_email = request.form.get("claimant_email", "").strip()
        claim_reason = request.form.get("claim_reason", "").strip()
        identifiable_features = request.form.get("identifiable_features", "").strip()
        secret_detail_answer = request.form.get("secret_detail_answer", "").strip()

        # Validate required fields
        if not claimant_name or not claimant_email or not claim_reason or not identifiable_features:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for("claim", item_id=item_id))

        # If item has a secret detail, verify the answer
        if item.secret_detail and not secret_detail_answer:
            flash("You must provide the secret detail to claim this item.", "danger")
            return redirect(url_for("claim", item_id=item_id))

        # Create claim request
        new_claim = ClaimRequest(
            item_id=item_id,
            claimant_name=claimant_name,
            claimant_email=claimant_email,
            claim_reason=claim_reason,
            identifiable_features=identifiable_features,
            secret_detail_answer=secret_detail_answer,
            status="pending"
        )

        db.session.add(new_claim)
        db.session.commit()

        flash(f"Claim request submitted! We'll review your claim and verify your details. You'll receive an email update at {claimant_email}.", "success")
        return redirect(url_for("browse"))

    # Get all claims for this item
    claims = ClaimRequest.query.filter_by(item_id=item_id).all()
    pending_claims = [c for c in claims if c.status == "pending"]
    approved_claims = [c for c in claims if c.status == "approved"]

    return render_template("claim.html", item=item, pending_claims=pending_claims, approved_claims=approved_claims)


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
        school = request.form.get("school", "South Forsyth")  # Default fallback
        item = Item(name=name, description=description, location=location, school=school, status='Found', approved=True)
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
    # For production deployment (like Render)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)