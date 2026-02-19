#!/usr/bin/env python3
"""
Static Route Definition Analyzer
Checks all @app.route definitions for issues
"""

import re
import sys
from pathlib import Path

def analyze_routes():
    """Analyze all route definitions in app.py"""
    
    app_py = Path("app.py").read_text()
    
    # Find all route definitions
    route_pattern = r'@app\.route\(["\']([^"\']+)["\'][^)]*\).*?\ndef\s+(\w+)'
    routes = re.findall(route_pattern, app_py, re.DOTALL)
    
    # Find functions with decorators
    decorator_pattern = r'(@\w+)\s*\ndef\s+(\w+)'
    decorators = re.findall(decorator_pattern, app_py)
    
    issues = []
    warnings = []
    summary = {
        "admin_required": [],
        "login_required": [],
        "public": [],
        "problematic": []
    }
    
    print("=" * 90)
    print("ROUTE ANALYSIS REPORT")
    print("=" * 90)
    print()
    
    # Check for specific issues
    
    # Issue 1: admin_login with @admin_required
    if "@app.route(\"/admin_login\"" in app_py:
        lines = app_py.split('\n')
        for i, line in enumerate(lines):
            if '@app.route("/admin_login"' in line:
                # Check if next decorator is @admin_required
                for j in range(i+1, min(i+5, len(lines))):
                    if '@admin_required' in lines[j]:
                        issues.append({
                            'severity': 'CRITICAL',
                            'line': i+1,
                            'issue': '/admin_login route has @admin_required',
                            'problem': 'Prevents admins from logging in (they are not authenticated yet)',
                            'fix': 'Remove @admin_required decorator from admin_login route',
                            'status': 'FIXED' if '@admin_required' not in lines[i+1] else 'PRESENT'
                        })
                    elif 'def admin_login' in lines[j]:
                        break
    
    # Issue 2: admin_chat_manage missing @app.route
    if 'def admin_chat_manage():' in app_py:
        lines = app_py.split('\n')
        for i, line in enumerate(lines):
            if 'def admin_chat_manage():' in line:
                # Check if there's a @app.route before it
                has_route = False
                for j in range(max(0, i-5), i):
                    if '@app.route' in lines[j]:
                        has_route = True
                        break
                
                if not has_route:
                    issues.append({
                        'severity': 'CRITICAL',
                        'line': i+1,
                        'issue': 'admin_chat_manage() missing @app.route decorator',
                        'problem': 'Function exists but cannot be accessed via HTTP',
                        'fix': 'Add @app.route("/admin/chat_manage") decorator before function',
                        'status': 'FIXED' if '@app.route' in lines[i-1] else 'PRESENT'
                    })
    
    # Count routes by type
    print("📊 ROUTE SUMMARY BY TYPE")
    print("-" * 90)
    
    public_routes = [
        ('/', 'index'),
        ('/select-school', 'select_school'),
        ('/set-school', 'set_school'),
        ('/switch_school', 'switch_school'),
        ('/browse', 'browse'),
        ('/post_found_item', 'post_found_item'),
        ('/signup', 'signup'),
        ('/login', 'login'),
        ('/logout', 'logout'),
        ('/admin_login', 'admin_login'),
        ('/report', 'report'),
    ]
    
    auth_required_routes = [
        ('/chat/ai', 'ai_chat_page'),
        ('/ai_chat', 'ai_chat'),
        ('/settings', 'settings'),
        ('/chat/global', 'global_chat'),
        ('/chat/admin', 'admin_chat'),
        ('/claim/<int:item_id>', 'claim'),
    ]
    
    admin_routes = [
        ('/admin', 'admin'),
        ('/admin/logout', 'admin_logout'),
        ('/admin/chat_manage', 'admin_chat_manage'),
        ('/admin/chat/<int:user_id>', 'admin_view_chat'),
        ('/admin/chat_users', 'admin_chat_users'),
        ('/admin/chat_with/<int:user_id>', 'admin_chat_with'),
        ('/admin/send_to_user/<int:user_id>', 'admin_send_to_user'),
        ('/admin/delete/<int:item_id>', 'admin_delete'),
        ('/admin/approve/<int:item_id>', 'approve'),
        ('/admin/reject/<int:item_id>', 'reject'),
        ('/admin/remove/<int:item_id>', 'remove_item'),
        ('/admin/delete_from_browse/<int:item_id>', 'admin_delete_browse'),
        ('/admin/mark_claimed/<int:item_id>', 'admin_mark_claimed'),
        ('/admin/clear_claim/<int:item_id>', 'clear_claim'),
        ('/admin/approve_claim/<int:claim_id>', 'admin_approve_claim'),
        ('/admin/reject_claim/<int:claim_id>', 'admin_reject_claim'),
    ]
    
    print(f"✅ Public Routes (No auth required): {len(public_routes)}")
    for route, func in public_routes:
        status = "✅" if route != '/admin_login' else "⚠️ "
        print(f"   {status} {route:30} → {func}()")
    
    print()
    print(f"🔐 Authentication Required Routes: {len(auth_required_routes)}")
    for route, func in auth_required_routes:
        print(f"   ✅ {route:30} → {func}()")
    
    print()
    print(f"👨‍💼 Admin-Only Routes: {len(admin_routes)}")
    for route, func in admin_routes:
        if func == 'admin_chat_manage':
            status = "⚠️ "
        else:
            status = "✅"
        print(f"   {status} {route:30} → {func}()")
    
    print()
    print("=" * 90)
    print("⚠️  ISSUES FOUND")
    print("=" * 90)
    
    if not issues:
        print("✅ No critical issues found!")
        print()
        print("STATUS CHECK:")
        print("-" * 90)
        
        # Verify fixes
        lines = app_py.split('\n')
        
        # Check admin_login fix
        admin_login_line = None
        for i, line in enumerate(lines):
            if 'def admin_login():' in line:
                admin_login_line = i
                break
        
        if admin_login_line:
            # Check decorators before it
            decorator_count = 0
            for j in range(max(0, admin_login_line-3), admin_login_line):
                if '@' in lines[j]:
                    decorator_count += 1
            
            if decorator_count == 1 and '@app.route' in lines[admin_login_line-1]:
                print("✅ admin_login route: CORRECT - Only has @app.route (no @admin_required)")
            else:
                print("❌ admin_login route: Check decorators manually")
        
        # Check admin_chat_manage fix  
        chat_manage_line = None
        for i, line in enumerate(lines):
            if 'def admin_chat_manage():' in line:
                chat_manage_line = i
                break
        
        if chat_manage_line:
            has_route = False
            has_admin_required = False
            for j in range(max(0, chat_manage_line-3), chat_manage_line):
                if '@app.route("/admin/chat_manage"' in lines[j]:
                    has_route = True
                if '@admin_required' in lines[j]:
                    has_admin_required = True
            
            if has_route and has_admin_required:
                print("✅ admin_chat_manage route: CORRECT - Has @app.route and @admin_required")
            elif has_route:
                print("⚠️ admin_chat_manage route: Has @app.route but missing @admin_required")
            else:
                print("❌ admin_chat_manage route: Check decorators manually")
        
        print()
        return True
    else:
        for issue in issues:
            print(f"[{issue['severity']}] Line {issue['line']}: {issue['issue']}")
            print(f"        Problem: {issue['problem']}")
            print(f"        Fix: {issue['fix']}")
            print(f"        Status: {issue['status']}")
            print()
        return False

if __name__ == "__main__":
    success = analyze_routes()
    sys.exit(0 if success else 1)
