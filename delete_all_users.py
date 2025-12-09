from app import app, db, User

with app.app_context():
    print("=== Deleting All User Accounts ===\n")
    
    # Get all users
    all_users = User.query.all()
    print(f"Found {len(all_users)} users:")
    for user in all_users:
        print(f"  - {user.name} ({user.email})")
    
    # Delete all users
    User.query.delete()
    db.session.commit()
    
    print(f"\n✓ Deleted all {len(all_users)} user accounts")
    
    # Verify deletion
    remaining = User.query.count()
    print(f"Remaining users: {remaining}")
