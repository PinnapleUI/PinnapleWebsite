from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime
import re

app = Flask(__name__)
CORS(app)

# Database initialization
def init_db():
    conn = sqlite3.connect('pinnapleui.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Newsletter subscribers table
    c.execute('''CREATE TABLE IF NOT EXISTS newsletter
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  updates BOOLEAN DEFAULT 1,
                  releases BOOLEAN DEFAULT 1,
                  subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

# Helper functions
def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${pwd_hash}"

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        salt, pwd_hash = stored_hash.split('$')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except:
        return False

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username (alphanumeric, 3-20 chars)"""
    return len(username) >= 3 and len(username) <= 20 and username.isalnum()

def validate_password(password):
    """Validate password strength (min 8 chars)"""
    return len(password) >= 8

# API Routes
@app.route('/api/newsletter/subscribe', methods=['POST'])
def newsletter_subscribe():
    """Newsletter subscription endpoint"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        updates = data.get('updates', True)
        releases = data.get('releases', True)
        
        # Validate email
        if not email or not validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email address'}), 400
        
        conn = sqlite3.connect('pinnapleui.db')
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO newsletter (email, updates, releases) VALUES (?, ?, ?)',
                     (email, updates, releases))
            conn.commit()
            return jsonify({'success': True, 'message': 'Successfully subscribed to newsletter'})
        except sqlite3.IntegrityError:
            return jsonify({'success': False, 'error': 'Email already subscribed'}), 400
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    """User account creation endpoint"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        terms = data.get('terms', False)
        
        # Validate inputs
        if not terms:
            return jsonify({'success': False, 'error': 'Please agree to the Terms of Service'}), 400
        
        if not username or not validate_username(username):
            return jsonify({'success': False, 'error': 'Username must be 3-20 alphanumeric characters'}), 400
        
        if not email or not validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email address'}), 400
        
        if not password or not validate_password(password):
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        
        # Hash password
        password_hash = hash_password(password)
        
        conn = sqlite3.connect('pinnapleui.db')
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                     (username, email, password_hash))
            conn.commit()
            return jsonify({'success': True, 'message': 'Account created successfully'})
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return jsonify({'success': False, 'error': 'Username already taken'}), 400
            elif 'email' in str(e):
                return jsonify({'success': False, 'error': 'Email already registered'}), 400
            else:
                return jsonify({'success': False, 'error': 'Registration failed'}), 400
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/signin', methods=['POST'])
def signin():
    """User sign in endpoint"""
    try:
        data = request.get_json()
        email_or_username = data.get('emailOrUsername', '').strip()
        password = data.get('password', '')
        
        if not email_or_username or not password:
            return jsonify({'success': False, 'error': 'Email/username and password are required'}), 400
        
        conn = sqlite3.connect('pinnapleui.db')
        c = conn.cursor()
        
        # Try to find user by email or username
        c.execute('SELECT id, username, email, password_hash FROM users WHERE email = ? OR username = ?',
                 (email_or_username.lower(), email_or_username))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        user_id, username, email, password_hash = user
        
        # Verify password
        if not verify_password(password, password_hash):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Return user data (without password)
        return jsonify({
            'success': True,
            'message': 'Successfully signed in',
            'user': {
                'id': user_id,
                'username': username,
                'email': email
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    """Update user profile endpoint"""
    try:
        data = request.get_json()
        user_id = data.get('userId')
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        
        if not user_id or not username or not email:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        if not validate_username(username):
            return jsonify({'success': False, 'error': 'Username must be 3-20 alphanumeric characters'}), 400
        
        if not validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email address'}), 400
        
        conn = sqlite3.connect('pinnapleui.db')
        c = conn.cursor()
        
        try:
            c.execute('UPDATE users SET username = ?, email = ? WHERE id = ?',
                     (username, email, user_id))
            conn.commit()
            
            if c.rowcount == 0:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            return jsonify({'success': True, 'message': 'Profile updated successfully'})
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return jsonify({'success': False, 'error': 'Username already taken'}), 400
            elif 'email' in str(e):
                return jsonify({'success': False, 'error': 'Email already registered'}), 400
            else:
                return jsonify({'success': False, 'error': 'Update failed'}), 400
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    """Change user password endpoint"""
    try:
        data = request.get_json()
        user_id = data.get('userId')
        current_password = data.get('currentPassword', '')
        new_password = data.get('newPassword', '')
        
        if not user_id or not current_password or not new_password:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        if not validate_password(new_password):
            return jsonify({'success': False, 'error': 'New password must be at least 8 characters'}), 400
        
        conn = sqlite3.connect('pinnapleui.db')
        c = conn.cursor()
        
        # Get current password hash
        c.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        current_hash = result[0]
        
        # Verify current password
        if not verify_password(current_password, current_hash):
            conn.close()
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
        
        # Hash new password
        new_hash = hash_password(new_password)
        
        # Update password
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    """Delete user account endpoint"""
    try:
        data = request.get_json()
        user_id = data.get('userId')
        
        if not user_id:
            return jsonify({'success': False, 'error': 'User ID required'}), 400
        
        conn = sqlite3.connect('pinnapleui.db')
        c = conn.cursor()
        
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        if c.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        conn.close()
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'message': 'PinnapleUI API is running'})

if __name__ == '__main__':
    init_db()
    print("Starting PinnapleUI server...")
    print("API endpoints:")
    print("  POST /api/newsletter/subscribe")
    print("  POST /api/signup")
    print("  POST /api/signin")
    print("  POST /api/update-profile")
    print("  POST /api/change-password")
    print("  POST /api/delete-account")
    print("  GET  /api/health")
    app.run(debug=True, port=5000)
