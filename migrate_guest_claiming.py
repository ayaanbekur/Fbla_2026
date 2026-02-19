#!/usr/bin/env python3
"""
Migration script to add new columns for guest posting and enhanced claiming.
Run this script to update your database schema.
"""

import os
import sys
from dotenv import load_dotenv

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from init_db import db, Item, ClaimRequest
from app import app

# Load environment variables
load_dotenv()

def run_migration():
    """Apply migration to add new columns."""
    with app.app_context():
        try:
            # Check and add columns to Item table
            with db.engine.connect() as conn:
                inspector = db.inspect(db.engine)
                
                # Check Item table columns
                item_columns = [col['name'] for col in inspector.get_columns('item')]
                
                if 'secret_detail' not in item_columns:
                    print("Adding 'secret_detail' column to Item table...")
                    conn.execute('ALTER TABLE item ADD COLUMN secret_detail TEXT')
                    conn.commit()
                    print("✓ Added secret_detail column")
                else:
                    print("✓ secret_detail column already exists")
                
                if 'guest_email' not in item_columns:
                    print("Adding 'guest_email' column to Item table...")
                    conn.execute('ALTER TABLE item ADD COLUMN guest_email VARCHAR(120)')
                    conn.commit()
                    print("✓ Added guest_email column")
                else:
                    print("✓ guest_email column already exists")
                
                # Check ClaimRequest table columns
                claim_columns = [col['name'] for col in inspector.get_columns('claim_request')]
                
                if 'claim_reason' not in claim_columns:
                    print("Adding 'claim_reason' column to ClaimRequest table...")
                    conn.execute('ALTER TABLE claim_request ADD COLUMN claim_reason TEXT')
                    conn.commit()
                    print("✓ Added claim_reason column")
                else:
                    print("✓ claim_reason column already exists")
                
                if 'identifiable_features' not in claim_columns:
                    print("Adding 'identifiable_features' column to ClaimRequest table...")
                    conn.execute('ALTER TABLE claim_request ADD COLUMN identifiable_features TEXT')
                    conn.commit()
                    print("✓ Added identifiable_features column")
                else:
                    print("✓ identifiable_features column already exists")
                
                if 'secret_detail_answer' not in claim_columns:
                    print("Adding 'secret_detail_answer' column to ClaimRequest table...")
                    conn.execute('ALTER TABLE claim_request ADD COLUMN secret_detail_answer TEXT')
                    conn.commit()
                    print("✓ Added secret_detail_answer column")
                else:
                    print("✓ secret_detail_answer column already exists")
                
                if 'claimant_email' not in claim_columns:
                    print("Adding 'claimant_email' column to ClaimRequest table...")
                    conn.execute('ALTER TABLE claim_request ADD COLUMN claimant_email VARCHAR(120)')
                    conn.commit()
                    print("✓ Added claimant_email column")
                else:
                    print("✓ claimant_email column already exists")
            
            print("\n✅ Migration completed successfully!")
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            print("\nNote: If you're using SQLite, you may need to use SQLAlchemy's")
            print("migration tools. Alternatively, you can:")
            print("1. Delete site.db to start fresh, OR")
            print("2. Use a migration tool like Alembic")
            sys.exit(1)

if __name__ == "__main__":
    print("=" * 60)
    print("Lost & Found Database Migration")
    print("=" * 60)
    print("\nThis script will add new columns to support guest posting")
    print("and enhanced claiming features.\n")
    
    run_migration()
