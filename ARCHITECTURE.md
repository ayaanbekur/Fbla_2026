# 📊 Feature Architecture & Data Flow

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Lost & Found Platform                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐          ┌──────────────┐     ┌────────────┐ │
│  │   GUESTS     │          │   LOGGED-IN  │     │   ADMINS   │ │
│  │  (Posters)   │          │    USERS     │     │  (Review)  │ │
│  └──────────────┘          └──────────────┘     └────────────┘ │
│        │                          │                     │       │
│        │                          │                     │       │
│        ▼                          ▼                     ▼       │
│  ┌────────────────────────────────────────────────────────┐   │
│  │              Navigation / Routes                       │   │
│  ├────────────────────────────────────────────────────────┤   │
│  │ • /post_found_item (GET, POST)  ← NEW!                │   │
│  │ • /browse                                              │   │
│  │ • /claim/<id> (GET, POST)       ← ENHANCED!           │   │
│  │ • /admin                                               │   │
│  └────────────────────────────────────────────────────────┘   │
│        │                          │                     │       │
│        ▼                          ▼                     ▼       │
│  ┌──────────────┐          ┌──────────────┐     ┌────────────┐ │
│  │ POST FORM    │          │ CLAIM FORM   │     │ ADMIN      │ │
│  │ (templates/) │          │ (templates/) │     │ DASHBOARD  │ │
│  └──────────────┘          └──────────────┘     └────────────┘ │
│        │                          │                     │       │
│        ▼                          ▼                     ▼       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Flask Application                       │  │
│  │  (app.py routes, form handling, validation)             │  │
│  └──────────────────────────────────────────────────────────┘  │
│        │                          │                     │       │
│        ▼                          ▼                     ▼       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │               SQLAlchemy ORM (init_db.py)               │  │
│  │  • Item (+ secret_detail, guest_email)                  │  │
│  │  • ClaimRequest (+ claim_reason, features, etc.)        │  │
│  │  • User, Message, AIChat, Report                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│        │                          │                     │       │
│        ▼                          ▼                     ▼       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 Database (PostgreSQL)                    │  │
│  │  • item table (+ secret_detail, guest_email columns)   │  │
│  │  • claim_request table (+ new columns for details)     │  │
│  │  • users, messages, ai_chat, reports, etc.            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Guest Posting Flow

```
GUEST VISITOR
     │
     ▼
┌─ Click "📦 Post Found Item" ─┐
│                              │
├─ No login required           │
│                              │
├─ Access: /post_found_item    │
│  (GET)                       │
│                              │
└──────────────┬───────────────┘
               │
               ▼
        ┌──────────────────┐
        │  FORM PAGE       │
        │  (HTML Template) │
        ├──────────────────┤
        │ • Item Name      │
        │ • Description    │
        │ • Location       │
        │ • School         │
        │ • Image Upload   │
        │ 🔐 Secret Detail │
        │ • Email Address  │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │ SUBMIT FORM      │
        │ (POST request)   │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │ FLASK VALIDATION │
        ├──────────────────┤
        │ ✓ All fields OK? │
        │ ✓ Valid email?   │
        │ ✓ File uploaded? │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │ SAVE TO DATABASE │
        ├──────────────────┤
        │ INSERT INTO item │
        │  name          ✓ │
        │  description   ✓ │
        │  location      ✓ │
        │  school        ✓ │
        │  image_file    ✓ │
        │  secret_detail ✓ │ ← NEW!
        │  guest_email   ✓ │ ← NEW!
        │  owner_id=NULL ✓ │
        │  approved=FALSE  │ ← Needs admin review
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │ REDIRECT TO      │
        │ SUCCESS PAGE     │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │ ADMIN DASHBOARD  │
        │ Reviews items    │
        │ Approves/Rejects │
        └────────┬─────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
    APPROVED         REJECTED
      │                   │
      ▼                   ▼
  Item appears         Item deleted
  in browse            Sent email to
  (approved=TRUE)      guest explaining

```

---

## Enhanced Claim Flow

```
USER (Any - logged in or guest)
     │
     ▼
┌─ Browse Items Page ─┐
│ Click "Claim" on    │
│ an item             │
└─────────┬───────────┘
          │
          ▼
   ┌──────────────────┐
   │ /claim/<id>      │
   │ GET request      │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────────────┐
   │ ITEM DISPLAY             │
   ├──────────────────────────┤
   │ [Item Image]             │
   │ Name: Blue Backpack      │
   │ Description: ...         │
   │ Location: Cafeteria      │
   │ Status: Found            │
   │                          │
   │ 🔐 Secret Detail Notice: │
   │ "To prove ownership,     │
   │  you must describe a     │
   │  secret detail that      │
   │  only the real owner     │
   │  would know"             │
   └────────┬─────────────────┘
            │
            ▼
   ┌──────────────────────────┐
   │ CLAIM FORM               │
   ├──────────────────────────┤
   │ Your Name          ✓ REQ │
   │ Your Email         ✓ REQ │
   │ Why It's Yours     ✓ REQ │
   │ Identifiable       ✓ REQ │
   │  Features               │
   │ Secret Detail      ✓ REQ │ ← NEW!
   │  Answer - if item  │   (only if item
   │  has secret detail │    has secret)
   └────────┬───────────────┘
            │
            ▼
   ┌──────────────────────┐
   │ USER FILLS FORM      │
   └────────┬─────────────┘
            │
            ▼
   ┌──────────────────────┐
   │ CLICK SUBMIT         │
   │ POST request         │
   └────────┬─────────────┘
            │
            ▼
   ┌──────────────────────────┐
   │ FLASK VALIDATION         │
   ├──────────────────────────┤
   │ ✓ Name provided?         │
   │ ✓ Email valid?           │
   │ ✓ Reason provided?       │
   │ ✓ Features provided?     │
   │ ✓ Secret answer IF       │
   │   secret exists?         │
   └────────┬─────────────────┘
            │
            ▼
   ┌──────────────────────┐
   │ CREATE CLAIM REQUEST │
   │ INSERT INTO          │
   │  claim_request:      │
   │  ├─ item_id         │
   │  ├─ claimant_name   │
   │  ├─ claimant_email ✓│ ← NEW!
   │  ├─ claim_reason   ✓│ ← NEW!
   │  ├─ identifiable.. ✓│ ← NEW!
   │  ├─ secret_detail  ✓│ ← NEW!
   │  │  _answer        │
   │  └─ status=pending │
   └────────┬────────────┘
            │
            ▼
   ┌──────────────────────┐
   │ SUCCESS MESSAGE      │
   │ "Claim submitted!    │
   │  Admin will review"  │
   └────────┬─────────────┘
            │
            ▼
   ┌──────────────────────┐
   │ ADMIN REVIEWS        │
   ├──────────────────────┤
   │ Sees all claim info: │
   │ • Reason             │
   │ • Features described │
   │ • Secret answer      │
   │ • Secret detail      │
   │  (what was posted)   │
   │                      │
   │ COMPARES answers     │
   │ Do they match?       │
   └────────┬─────────────┘
            │
      ┌─────┴──────┐
      ▼            ▼
    YES           NO
  APPROVE       REJECT
    │             │
    ▼             ▼
  Item status   Claim marked
  = Claimed     status=rejected
  Send email    Send email
  to claimant   explaining

```

---

## Secret Detail Verification

```
┌─────────────────────────────────────────────┐
│  ITEM POSTER (Guest or User)                │
├─────────────────────────────────────────────┤
│ Finds item & decides: keep secret detail    │
│                                             │
│ In description:                             │
│ "Blue North Face backpack, one small        │
│  tear in the bottom corner, has             │
│  several stickers on it"                    │
│                                             │
│ Secret Detail (NOT in description):         │
│ "The stickers are:                          │
│  - A cat sticker on the front left          │
│  - A Tokyo skyline sticker on the back      │
│  - An anime character on the side"          │
└────────────────┬────────────────────────────┘
                 │
                 ▼
        ┌────────────────────┐
        │ Item Posted        │
        │ item_id=5          │
        │ secret_detail=     │
        │ "cat, tokyo,       │
        │  anime stickers"   │
        │ approved=FALSE     │
        └────────┬───────────┘
                 │
                 ▼
        ┌────────────────────┐
        │ Admin Approves     │
        │ approved=TRUE      │
        └────────┬───────────┘
                 │
                 ▼
        ┌────────────────────┐
        │ Item in Browse     │
        │ Shows description  │
        │ (NOT secret)       │
        └────────┬───────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ CLAIMANT (Lost item owner)                  │
├─────────────────────────────────────────────┤
│ Sees item and clicks "Claim"                │
│                                             │
│ Fills claim form:                           │
│ Name: John Smith                            │
│ Email: john@school.edu                      │
│ Why: "I left it in the library study room   │
│       Tuesday afternoon"                    │
│ Features: "Blue NF backpack with small      │
│           tear bottom corner, has stickers" │
│                                             │
│ Secret Detail Answer:                       │
│ "The stickers are a cat, Tokyo skyline,     │
│  and anime character"                       │
└────────────────┬────────────────────────────┘
                 │
                 ▼
        ┌────────────────────┐
        │ Claim Submitted    │
        │ status=pending     │
        └────────┬───────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ ADMIN REVIEWS                               │
├─────────────────────────────────────────────┤
│ Compares:                                   │
│                                             │
│ Posted Secret Detail:                       │
│ "cat, tokyo, anime stickers"                │
│                                             │
│ Claimant Said:                              │
│ "cat, Tokyo skyline, anime character"       │
│                                             │
│ ✅ MATCHES!!!                               │
│                                             │
│ Other checks:                               │
│ ✅ Reason sounds legit                      │
│ ✅ Features match description               │
│ ✅ Secret detail matches perfectly          │
│                                             │
│ → APPROVE CLAIM                             │
└────────────────┬────────────────────────────┘
                 │
                 ▼
        ┌────────────────────┐
        │ Claim Approved     │
        │ Item Status=       │
        │  Claimed           │
        │ Claimant=          │
        │  John Smith        │
        │                    │
        │ Email sent to      │
        │ john@school.edu    │
        │ "Your claim was    │
        │  approved!"        │
        └────────────────────┘
```

---

## Data Model Relationships

```
User
├── owns Items (one-to-many)
│   └── has many ClaimRequests (one-to-many)
│       └── submitted by Claimant (email/user)
│
Guest Item (owner_id = NULL)
├── Has guest_email instead of user
├── Has secret_detail for verification
└── has many ClaimRequests (one-to-many)
    └── Claimants must answer secret detail

Item
├── id (primary key)
├── name, description, location, school
├── status (Found, Lost, Claimed, Removed)
├── approved (needs admin review)
├── image_filename (optional)
├── owner_id FK→User (nullable for guests)
├── guest_email (for guest posters)
├─ secret_detail (THE HIDDEN DETAIL)
└── claimant (name of approver)

ClaimRequest
├── id (primary key)
├── item_id FK→Item
├── claimant_name
├── claimant_email (new!)
├── status (pending, approved, rejected)
├── claim_reason (new!)
├── identifiable_features (new!)
├── secret_detail_answer (new!)
└── timestamp
```

---

## New Features at a Glance

### 🌳 Feature Tree

```
Lost & Found Platform
│
├─ 👥 Guest Posting
│  ├─ Route: /post_found_item
│  ├─ Form: post_found_item.html
│  ├─ Fields:
│  │  ├─ name (required)
│  │  ├─ description (required)
│  │  ├─ location
│  │  ├─ school
│  │  ├─ image (optional)
│  │  ├─ secret_detail (required) ← KEY
│  │  └─ email (required)
│  ├─ Database:
│  │  ├─ Item.guest_email
│  │  ├─ Item.secret_detail
│  │  └─ Item.owner_id = NULL
│  └─ Approval: Admin must approve before visible
│
├─ 📋 Enhanced Claiming
│  ├─ Route: /claim/<id>
│  ├─ Form: claim.html (updated)
│  ├─ Fields:
│  │  ├─ claimant_name (required)
│  │  ├─ claimant_email (required)
│  │  ├─ claim_reason (required)
│  │  ├─ identifiable_features (required)
│  │  └─ secret_detail_answer (required if secret exists)
│  ├─ Database:
│  │  ├─ ClaimRequest.claimant_email
│  │  ├─ ClaimRequest.claim_reason
│  │  ├─ ClaimRequest.identifiable_features
│  │  └─ ClaimRequest.secret_detail_answer
│  └─ Verification: Admin compares answers
│
└─ 🔐 Secret Detail System
   ├─ Posted by: Item finder
   ├─ Stored in: Item.secret_detail
   ├─ Verified by: Claimant answer
   ├─ Compared by: Admin
   ├─ Examples:
   │  ├─ Engraving text
   │  ├─ Lock screen image
   │  ├─ Sticker patterns
   │  └─ Unique damage/marks
   └─ Purpose: Prevent false claims
```

---

**Generated**: February 18, 2026
