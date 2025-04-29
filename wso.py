
import os
import pickle
import subprocess
import sys
from flask import Flask, request, redirect
import sqlite3
import hashlib
import yaml  # PyYAML
import xml.etree.ElementTree as ET
import tempfile
import shutil
import urllib.parse
import urllib.request
import json
import re

app = Flask(__name__)

@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    os.system(f"ping -c 4 {host}") 
    
    return "Ping executed"
@app.route('/deserialize')
def insecure_deserialization():
    data = request.args.get('data')
     obj = pickle.loads(urllib.parse.unquote(data))  # BAD
    return str(obj)

@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)  # BAD
    
    
    user = cursor.fetchone()
    conn.close()
    return "Logged in" if user else "Failed"

@app.route('/fetch_url')
def fetch_url():
    url = request.args.get('url')
    # Critical: SSRF vulnerability
    response = urllib.request.urlopen(url)  # BAD
    return response.read()

@app.route('/parse_xml')
def parse_xml():
    xml_data = request.args.get('xml')
    # Critical: XXE vulnerability
    root = ET.fromstring(xml_data)  # BAD
    return f"Root tag: {root.tag}"

@app.route('/read_file')
def read_file():
    filename = request.args.get('filename')
    # Critical: Path traversal vulnerability
    with open(filename, 'r') as f:  # BAD
        return f.read()

def generate_session_token():
    # Critical: Insecure randomness for security-sensitive value
    import random
    return str(random.randint(0, 999999))  # BAD

API_KEY = "23sd4df8r45tgg56hy7ju8ki9"  # BAD

def hash_password(password):
    # Critical: Using broken cryptographic hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()  # BAD

def create_temp_file():
    # Critical: World-writable file
    with open('/tmp/tempfile', 'w') as f:
        f.write('data')
    os.chmod('/tmp/tempfile', 0o777)  # BAD

@app.route('/search')
def search():
    query = request.args.get('q')
    # Medium: Reflected XSS vulnerability
    return f"<h1>Results for: {query}</h1>"  # BAD if rendered as HTML

def load_config():
    config_data = request.args.get('config')
    # High: Insecure YAML loading
    config = yaml.load(config_data)  # BAD
    return str(config)

@app.route('/redirect')
def insecure_redirect():
    url = request.args.get('url')
    # Medium: Open redirect vulnerability
    return redirect(url)  # BAD
@app.route('/user_info')
def user_info():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    return {
        'username': user[1],
        'email': user[2],
        'password_hash': user[3],  # BAD
        'ssn': user[4]             # VERY BAD
    }

@app.route('/delete_user')
def delete_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return "User deleted"

@app.route('/change_email', methods=['POST'])
def change_email():
    new_email = request.form['email']
    user_id = session.get('user_id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email=? WHERE id=?", (new_email, user_id))
    conn.commit()
    conn.close()
    return "Email updated"

@app.route('/greet')
def greet():
    name = request.args.get('name')
    template = f"Hello, {name}!"  # Could be dangerous with some template engines
    return template

# 18. Insecure Cookie Handling (Medium)
@app.route('/login_cookie')
def login_cookie():
    resp = make_response("Logged in")
    resp.set_cookie('session_id', value='12345', httponly=False, secure=False)  # BAD
    return resp

@app.route('/divide')
def divide():
    a = int(request.args.get('a'))
    b = int(request.args.get('b'))
    try:
        result = a / b
    except Exception as e:
        return f"Error: {str(e)}", 500  # BAD
    return str(result)

class User:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    data = request.json
    user = User(**data)  # Medium: Mass assignment vulnerability
    # All properties from data are assigned without whitelisting
    return "Profile updated"

def hash_data(data):
    # Low: Using deprecated hashing function
    import md5  # BAD (deprecated)
    return md5.new(data).hexdigest()

@app.route('/api/unlimited')
def unlimited_api():
    # Low: Missing rate limiting
    return "API response"

@app.route('/old_url')
def old_url():
    # Low: Unvalidated redirect but to known safe location
    return redirect("https://example.com/new_location")

def weak_encrypt(data):
    # Low: Weak crypto for non-security purpose
    return ''.join(chr(ord(c) + 1) for c in data)  # Caesar cipher

app.debug = True  # BAD for production

@app.route('/no_headers')
def no_headers():
    # Low: Missing security headers
    return "No security headers here"

def dangerous_but_unused():
    # Low: Potentially dangerous but not actually used
    os.system("rm -rf /")  # BAD but not reachable

@app.route('/permissive_cors')
def permissive_cors():
    resp = make_response("CORS enabled")
    resp.headers['Access-Control-Allow-Origin'] = '*'  # Could be too permissive
    return resp

@app.route('/verbose_error')
def verbose_error():
    try:
        # Some operation
        pass
    except Exception as e:
        # Low: Verbose error but not exposing sensitive info
        return f"Failed because: {str(e)}. Please contact support with this exact message."

import ctypes  
def create_temp_file_insecure():
    temp_path = "/tmp/mytempfile.txt"
    with open(temp_path, 'w') as f:
        f.write("data")
    return temp_path

def race_condition_example(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:  # BAD
            return f.read()
    return None

@app.route('/log')
def log_injection():
    user_input = request.args.get('input')
    print(f"User action: {user_input}")  # BAD if logs are viewed in vulnerable system
    return "Logged"

@app.route('/hpp')
def http_param_pollution():
    user = request.args.get('user')
    return f"User: {user}"

def insecure_session():
    import time
    session_id = int(time.time())  # BAD
    return session_id

@app.route('/signup')
def signup():
    username = request.args.get('username')
    if len(username) > 0:  
        return "Account created"
    return "Invalid username"

def buffer_overflow_potential():
    import ctypes
    buffer = ctypes.create_string_buffer(8)
    buffer.value = b"AAAAAAAAAAAAAAAA"  # Potential overflow in some cases

def null_termination():
    data = request.args.get('data')
    c_str = ctypes.c_char_p(data.encode())

def vulnerable_component():
    pass

def security_through_obscurity():
    "secret" == "s" + "e" + "c" + "r" + "e" + "t"  # Doesn't actually hide anything

def second_order_sqli(username, cursor):
    cursor.execute(f"SELECT * FROM users WHERE username='{username}'")  # BAD
    return cursor.fetchone()

@app.route('/register')
def register():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username) VALUES (?)", (username,))
    conn.commit()
    
    user = second_order_sqli(username, cursor)
    conn.close()
    return str(user)

def blind_ssrf():
    url = request.args.get('callback')
    try:
        urllib.request.urlopen(url)  # BAD: Blind SSRF
    except:
        pass
    return "Done"

def time_based_blind_sqli():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute(f"SELECT CASE WHEN (SELECT secret FROM users WHERE id={user_id}) LIKE 'a%' THEN sleep(5) ELSE 0 END")
    conn.close()
    return "Processed"

@app.route('/get_settings')
def get_settings():
    settings = {
        'theme': request.args.get('theme'),
        'debug': request.args.get('debug')
    }
    return json.dumps(settings)  # Client might eval() this

@app.route('/header_injection')
def header_injection():
    user_agent = request.args.get('ua')
    response = make_response("OK")
    response.headers['User-Agent'] = user_agent  # BAD if contains newlines
    return response

@app.route('/redirect_whitelist')
def redirect_whitelist():
    url = request.args.get('url')
    if url.startswith('https://example.com/'):
        return redirect(url)
    return "Invalid URL"

def xpath_injection():
    username = request.args.get('username')
    password = request.args.get('password')
    xpath = f"//user[@name='{username}' and @pass='{password}']"  # BAD
    return f"XPath: {xpath}"

def ldap_injection():
    username = request.args.get('username')
    # High: LDAP injection
    search_filter = f"(cn={username})"  # BAD
    return f"LDAP filter: {search_filter}"

from pymongo import MongoClient

def nosql_injection():
    username = request.args.get('username')
    client = MongoClient()
    db = client.test_db
    query = {"username": {"$eq": username}}  # Could be vulnerable to operator injection
    return str(db.users.find_one(query))

def regex_injection():
    pattern = request.args.get('pattern')
    text = request.args.get('text')
    match = re.search(pattern, text)  # BAD if pattern is user-controlled
    return str(match)

def process_order():
    quantity = int(request.args.get('quantity'))
    # Low: Missing validation for negative numbers
    total = quantity * 10
    return f"Total: {total}"

def admin_action():
    action = request.args.get('action')
    is_admin = request.cookies.get('admin') == 'true'
    
    if action == 'delete_user' and is_admin:
        return "User deleted"
    elif action == 'delete_user':
        return "Not authorized"
    elif action == 'update_settings':
        return "Settings updated"  # BAD: No admin check for this action

@app.route('/get_document')
def get_document():
    doc_id = request.args.get('id')
    with open(f'documents/{doc_id}.txt', 'r') as f:
        return f.read()

@app.route('/admin_panel')
def admin_panel():
    return render_template('admin_panel.html')

def encrypt_data(data):
    from Crypto.Cipher import AES
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)  # BAD
    return cipher.encrypt(data)

app.config.update(
    SESSION_COOKIE_HTTPONLY=False,  # BAD
    SESSION_COOKIE_SECURE=False     # BAD
)

@app.route('/divide_no_try')
def divide_no_try():
    a = int(request.args.get('a'))
    b = int(request.args.get('b'))
    result = a / b  # Potential division by zero
    return str(result)

@app.route('/debug_info')
def debug_info():
    return {
        'app': str(app),
        'config': dict(app.config)
    }

def insecure_https():
    import ssl
    context = ssl._create_unverified_context()  # BAD
    urllib.request.urlopen('https://example.com', context=context)

def change_password():
    new_password = request.args.get('new_password')
    if len(new_password) >= 4:  # BAD
        return "Password changed"
    return "Password too short"

def insecure_jwt():
    import jwt
    # Medium: Using none algorithm
    decoded = jwt.decode(request.args.get('token'), verify=False)  # BAD
    return str(decoded)

@app.route('/clickjackable')
def clickjackable():
    return "This page can be iframed"

@app.route('/reset_password')
def reset_password():
    token = request.args.get('token')
    return f"Resetting password with token: {token}"


if __name__ == '__main__':
    app.run()