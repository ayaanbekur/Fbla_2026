from app import app

test_client = app.test_client()

print("=== Testing Admin Login Flow ===\n")

# Step 1: Get the login page
print("1. Getting admin login page...")
response = test_client.get('/admin_login')
print(f"   Status: {response.status_code}")

# Step 2: Post credentials
print("\n2. Posting admin credentials...")
response = test_client.post('/admin_login', data={
    'username': 'ayaanbekur@gmail.com',
    'password': 'password123'
}, follow_redirects=False)

print(f"   Status: {response.status_code}")
print(f"   Location: {response.headers.get('Location', 'N/A')}")

# Step 3: Follow redirect
if response.status_code == 302:
    print("\n3. Following redirect...")
    response = test_client.get(response.headers.get('Location'))
    print(f"   Status: {response.status_code}")
    print(f"   Page contains 'admin': {'admin' in response.get_data(as_text=True).lower()}")
    
    # Check for session data
    with test_client:
        test_client.post('/admin_login', data={
            'username': 'ayaanbekur@gmail.com',
            'password': 'password123'
        })
        print(f"\n4. Checking session...")
        print(f"   session.get('admin'): {session.get('admin')}")
