#!/usr/bin/env python3
"""
Functional Route Testing
Tests actual route responses to ensure they work
"""

import sys
import os
from app import app, db
from flask_sqlalchemy import SQLAlchemy

def test_routes_functional():
    """Test routes by making actual HTTP requests to the Flask test client"""
    
    print("=" * 90)
    print("FUNCTIONAL ROUTE TESTING")
    print("=" * 90)
    print()
    
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        tests_passed = 0
        tests_failed = 0
        
        # Test routes
        test_cases = [
            # Public routes
            ("GET", "/", "Home page", 200),
            ("GET", "/select-school", "School selection", 200),
            ("GET", "/browse", "Browse items", 200),
            ("GET", "/post_found_item", "Post item form", 200),
            ("GET", "/signup", "Signup page", 200),
            ("GET", "/login", "Login page", 200),
            ("GET", "/admin_login", "Admin login page", 200),
            ("GET", "/report", "Report page", 200),
            
            # Routes that require auth (will redirect)
            ("GET", "/settings", "Settings (redirects to login)", (301, 302, 307, 308)),
            ("GET", "/chat/ai", "AI Chat (redirects to login)", (301, 302, 307, 308)),
            ("GET", "/chat/global", "Global chat (redirects)", (301, 302, 307, 308)),
            
            # Item/Claim routes
            ("GET", "/claim/1", "Claim form", (200, 404)),  # 404 if item doesn't exist
            
            # Admin routes (will redirect if not admin)
            ("GET", "/admin", "Admin dashboard", (302, 307, 308)),  # Will redirect
            ("GET", "/admin/chat_manage", "Admin chat manage", (302, 307, 308)),  # Will redirect
            ("GET", "/admin/chat_users", "Admin chat users", (302, 307, 308)),  # Will redirect
        ]
        
        print("📍 TESTING PUBLIC AND COMMON ROUTES")
        print("-" * 90)
        
        for method, route, description, expected_status in test_cases:
            try:
                if method == "GET":
                    response = client.get(route, follow_redirects=False)
                elif method == "POST":
                    response = client.post(route, follow_redirects=False)
                
                status = response.status_code
                
                # Check if status matches expected
                if isinstance(expected_status, tuple):
                    is_ok = status in expected_status
                else:
                    is_ok = status == expected_status
                
                if is_ok:
                    print(f"✅ {method:4} {route:30} → {status:3} - {description}")
                    tests_passed += 1
                else:
                    print(f"❌ {method:4} {route:30} → {status:3} (expected {expected_status}) - {description}")
                    tests_failed += 1
                    
            except Exception as e:
                print(f"❌ {method:4} {route:30} → ERROR - {str(e)}")
                tests_failed += 1
        
        print()
        print("=" * 90)
        print("TEST RESULTS")
        print("=" * 90)
        print(f"✅ Passed: {tests_passed}")
        print(f"❌ Failed: {tests_failed}")
        
        if tests_failed == 0:
            print()
            print("🎉 All routes are functioning correctly!")
            return True
        else:
            print()
            print(f"⚠️  {tests_failed} route(s) have issues")
            return False

if __name__ == "__main__":
    try:
        success = test_routes_functional()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
