import sqlite3

# Connect to SQLite database
conn = sqlite3.connect("vulnerabilities.db")
cursor = conn.cursor()

# Create table for patterns
cursor.execute("""
CREATE TABLE IF NOT EXISTS Patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    pattern TEXT,
    description TEXT,
    severity TEXT,
    secure_example TEXT              
)
""")

# Insert sample data 
cursor.executemany("""
INSERT INTO Patterns (name, pattern, description, severity, secure_example)
VALUES (?, ?, ?, ?, ?)
""", [
    #---- 1 Broken Access Control ---#
    (
        "Detecting Unrestricted Direct Object References (IDOR) in URLs",
        r'\/(users|account|profiles|orders)\/(\d+)',
        "Exposing internal object references (e.g., user IDs) in URLs without proper authorization checks.",
        "High",
        """Implement proper access control checks to verify user permissions before accessing resources.
       
        if user.has_permission(resource_id):
           return get_resource(resource_id)
        else:
           raise PermissionDenied('Access denied')"""
    ),

    (
        "Path Traversal",
        r'(\.\./|\.\.\\|%2e%2e/)',
        "Prevent attackers from accessing files outside the intended directory.",
        "High",
        """Use absolute paths and validate input to restrict file access.
        
        import os 
        base_dir = '/safe/directory/'
        full_path = os.path.abspath(os.path.join(base_dir, filename))

        if not full_path.startswith(base_dir):
            raise ValueError('Unauthorized file access attempt detected!')"""
    ),

    (
        "Missing Authorization",
        r'(route|path|url)\(.*?\)[^@]*?def\s+\w+\s*\(.*?\):',
        "Ensure proper authorization checks are implemented for protected resources.",
        "Critical",
        """Enforce authorization checks before granting access.
        from flask import request, abort

        @app.route('/admin')
        def admin_panel():
            if not request.user or not request.user.is_admin:
                abort(403)
            return 'Welcome, Admin!'
        """
    ),

    (
        "Cross-Site Request Forgery (CSRF)",
        r'<form[^>]*action=["\'][^"\']*["\'][^>]*>(?!.*csrf_token)',
        "Protect web applications from unauthorized actions performed on behalf of authenticated users.",
        "High",
        """Use CSRF tokens to validate legitimate requests.
        from django.views.decorators.csrf import csrf_protect

        @csrf_protect
        def secure_view(request):
            if request.method == 'POST':
                pass
        """
    ),
 
    (
        "Hardcoded Credentials",
        r'(password|secre|key)\s*=\s*["\'][^"\']+["\']',
        "Avoid storing sensitive information in plain text.",
        "High",
        """Storing sensitive information in environment variables or secure vaults.
        import os
        password = os.getenv('PASSWORD')
        """     
    ),

    #----- 2 Cryptographic Failure-------#
    (
        "Cleartext Transmission of Sensitive Information",
        r'requests\.(get|post|put|delete)\(\s*[\'\"]http://',  
        "Avoid transmitting sensitive data over unencrypted channels.",
        "High",
        """Use HTTPS instead of HTTP to encrypt data in transit.
    
        import requests
        response = requests.get('https://secure-api.com/data')
        """
    ),

    (
        "Use of weak or broken Cryptographic Algorithm",
        r'hashlib\.(md5|sha1)\(',  
        "Avoid using weak cryptographic algorithms like MD5, SHA-1, or DES.",
        "High",
        """Use stronger cryptographic algorithms like SHA-256 or AES.
    
        import hashlib
        hash = hashlib.sha256(b'secure_data').hexdigest()
        """
    ),

    (
        "Hardcoded Cryptographic Key",
        r'(\b[A-Za-z0-9+/=]{16,}\b)',  
        "Avoid hardcoding cryptographic keys in source code.",
        "Critical",
        """Store cryptographic keys in environment variables or secure vaults.

        import os
        secret_key = os.getenv('SECRET_KEY')
        """
    ),

    (
        "Weak Encoding for Passwords",
        r'base64\.b64encode\s*\(.*password',  
        "Avoid using weak encoding methods like Base64 for password storage.",
        "High",
        """Use secure password hashing functions like bcrypt or Argon2.
    
        from bcrypt import hashpw, gensalt
        hashed_pw = hashpw(b'my_secure_password', gensalt())
        """
    ),

    (
        "Unprotected Transport of Credentials",
        r'(\busername\s*=\s*["\'][^"\']+["\']|\bpassword\s*=\s*["\'][^"\']+["\'])',  
        "Avoid transmitting credentials in plaintext.",
        "Critical",
        """Use secure authentication methods and encrypted connections.

        import requests
        response = requests.post('https://secure-api.com/login', json={'username': os.getenv('USER'), 'password': os.getenv('PASS')})
        """
    ),

    #----- 3 Injection------#

    (
        "OS Command Injection",
        r'(\bos\.system\b|\bsubprocess\.(run|Popen|call|check_output)\b|\bos\.popen\b|\bcommands\.getoutput\b)',
        "Avoid executing system commands with user input, as it can lead to remote code execution.",
        "Critical",
        """Use `subprocess.run()` with `shell=False` to prevent command injection.
        Example:
        import subprocess
        result = subprocess.run(['ls', '-l'], capture_output=True, text=True)  
        """
    ),

    (
        "SQL Injection",
        r'["\']\s*\+\s*[\w.]+\s*\+\s*["\']',
        "Dynamic SQL queries constructed using concatenation can lead to SQL Injection vulnerabilites.",
        "Critical",
        """Use parameterized queries or prepared statements.
        Example:
        import sqlite3
        conn = sqlite3.connect('example.db')
        cursor = conn.cursor()
        query = 'SELECT * FROM users WHERE username = ?'
        cursor.execute(query, (username,))
        """
    ),

    (
        "LDAP Injection",
        r'(\bldap3\.Connection\b.*search\()',
        "Avoid directly inserting user input in LDAP queries. Use parameterized LDAP filters.",
        "High",
        """Use parameterized LDAP queries to avoid injection attacks.
        Example:
        from ldap3 import Connection, ALL
        conn = Connection('ldap://server', auto_bind=True)
        conn.search('dc=example,dc=com', '(uid={})'.format(ldap.escape_filter_chars(user_input))) 
        """
    ),

    (
        "Cross-Site Scripting (XSS)",
        r'(render_template\([^)]*\b\w+\s*\+\s*\w+)',
        "Avoid directly inserting user input into HTML responses without escaping.",
        "High",
        """Use Flask’s `escape()` function or template auto-escaping.
        Example:
        from flask import Flask, escape, render_template
        @app.route('/search')
        def search():
            query = escape(request.args.get('query', ''))
            return render_template('search.html', query=query)  
        """
    ),

    (
        "XPath Injection",
        r'(\bxpath\s*=\s*[\'\"].*?//\w+\s*\[.*?\+.*?\])',
        "Avoid constructing XPath queries with direct user input. Use parameterized XPath queries.",
        "High",
        """Use libraries that support parameterized XPath queries.
        Example:
        from lxml import etree
        tree = etree.parse("data.xml")
        query = "//user[@id=$id]"  # Safe
        result = tree.xpath(query, id=user_input)
        """
    ),

    (
        "XML Injection",
        r'(\bxml\.parse\b|\bET\.fromstring\b)',
        "Avoid parsing untrusted XML input without disabling external entity references (XXE).",
        "High",
        """Disable external entity expansion to prevent XXE attacks.
        Example:
        from defusedxml.ElementTree import parse
        tree = parse("data.xml")  
        """
    ),

    #----- 4 Insecure Design ------#
    (
        "Unrestricted File Upload",
        r'(\brequest\.files\b|\bsave\(\))',
        "Ensure uploaded files are validated and restricted to safe types.",
        "Critical",
        """Validate file types and use a secure upload directory.
        Example:
        from werkzeug.utils import secure_filename
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    
        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join('/uploads/', filename))  
        """
    ),

    (
        "Insufficiently Protected Credentials",
        r'(\bpassword\s*=\s*[\'\"].*[\'\"]|\bopen\s*\([\'\"].*\.txt[\'\"]\))',
        "Avoid storing credentials in plain text files or hardcoded variables.",
        "Critical",
        """Use environment variables or a secure credentials manager.
        Example:
        import os
        password = os.getenv('DB_PASSWORD')  
        """
    ),

    (
        "External Control of Critical State Data",
        r'(\bsession\[[\'\"]\w+[\'\"]\]\s*=\s*request\.(args|get_json|get_data)\.get)',
        "Avoid storing untrusted user input in session variables without validation.",
        "High",
        """Use signed session tokens or securely verify user input before storing it.
        Example:
        from flask import session, request
        user_role = request.args.get('role', 'guest')

        if user_role in ['admin', 'user']:
            session['role'] = user_role  
        """
    ),

    #----- 5 Security Misconfiguration ------#

    (
        "Improper Restriction of XML External Entity Reference",
        r'(<\?xml.*\s+DOCTYPE\s+\w+.*\s+SYSTEM\s*=\s*["\'][^"\']+["\'])',
        "Avoid enabling XML External Entities (XXE). Disable external entity references in XML parsers.",
        "Critical",
        """Disable XML external entities in parsers.
        Example:
        from lxml import etree
    
        parser = etree.XMLParser(resolve_entities=False)  # Disable XXE
        tree = etree.parse('file.xml', parser)
        """
    ),

    (
        "Sensitive Cookie Without 'HttpOnly' Flag",
        r'(set_cookie\([\'\"][^\'\"]+[\'\"][^;]*;[^;]*\s*Secure\s*;[^;]*\s*HttpOnly)',
        "Ensure that sensitive cookies have the 'HttpOnly' flag set.",
        "High",
        """Set the 'HttpOnly' flag on cookies to prevent JavaScript access.
        Example:
        response.set_cookie('session_id', 'abc123', httponly=True, secure=True)  # Safe cookie
        """
    ),

    #---- 6 Vulnerable and Outdated Components ---#

    (
        "Using Components with Known Vulnerabilities",
        r'(\bimport\s+\w+\b|\bfrom\s+\w+\s+import\s+\w+\b)',
        "Ensure that third-party libraries and components are updated and free of known vulnerabilities.",
        "Critical",
        """Use tools like Dependabot, Safety, or OWASP Dependency-Check to monitor and update dependencies.
        Example:
        # Install and check for vulnerabilities using `safety` library
        # safety check
        # Or use Dependabot in GitHub repositories for automated dependency updates
        """
    ),

    #---- 7 Identification and Authentication Failures ---#

    (
        "Authentication Bypass",
        r'(login\([^\)]*\)|authenticate\([^\)]*\))\s*[^a-zA-Z0-9]{0,5}\s*(true|false|1|0)\s*[^a-zA-Z0-9]{0,5}',
        "Ensure proper authentication checks are in place and not bypassed.",
        "Critical",
        """Make sure all authentication endpoints check user credentials and restrict access properly.
        Example:
        if not authenticate(user):
            raise Unauthorized("Access Denied")
        """
    ),

    (
        "Use of Hard-coded Password",
        r'(password\s*=\s*["\'][^"\']+["\'])',
        "Avoid hardcoding passwords in the source code.",
        "Critical",
        """Use environment variables or secure vaults for storing credentials.
        Example:
        import os
        password = os.getenv('DB_PASSWORD')  # Safe way to load password
        """
    ),

    (
        "Weak Password Requirements",
        r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}',  # Example for detecting weak password pattern
        "Ensure strong password policies are enforced (e.g., minimum length, uppercase, special characters).",
        "Critical",
        """Implement strong password requirements in your authentication system.
        Example:
        if len(password) < 8 or not any(c.isdigit() for c in password):
            raise ValueError("Weak password: Must contain at least 8 characters and a number.")
        """
    ),

    (
        "Insufficient Session Expiration",
        r'(session\.[^=]+)\s*=\s*["\'][^"\']+["\']',
        "Ensure that sessions expire after a reasonable time or after logout.",
        "High",
        """Implement session expiration after a set period of inactivity.
        Example:
        import time
        if time.time() - session['last_activity'] > 1800:
            session.clear()  # Expire session after 30 minutes
        """
    ),

    #---- 8 SOftware and Data Integrity Failure ---#

    (
        "Deserialization of Untrusted Data",
        r'\b(pickle|cPickle|marshal|shelve)\s*\.\s*(load|loads)\s*\(',
        "Avoid deserializing untrusted data, as it can lead to remote code execution (RCE).",
        "Critical",
        """Use safer serialization methods like JSON instead of pickle.
        Example:
        import json
        data = json.loads(user_input)  # Safe way to deserialize data
        """
    ),

    #---- 9 Security Logging and Monitoring Failures ---#

    (
        "Insertion of Sensitive Information into Log File",
        r'(\.log|log\()',
        "Avoid logging sensitive information (e.g., passwords, API keys, personal data).",
        "High",
        """Sanitize log data and avoid storing sensitive information in log files.
        Example:
        import logging
    
        logging.info("User login attempt")  # Safe logging
        """
    ),

    (
        "Improper Output Neutralization for Logs",
        r'log\.(info|debug|error|warn|critical)\(.*\+.*\)',
        "Avoid concatenating user input directly into logs to prevent log injection attacks.",
        "High",
        """Use structured logging instead of string concatenation to prevent log injection.
        Example:
        import logging

        logging.info("User input: %s", user_input)  # Safe logging
        """
    ),

    #---- 10 Server-Side Request Forgery (SSRF) ---#

    (
        "Server-Side Request Forgery (SSRF)",
        r'\b(url|endpoint|target)\s*=\s*["\'][^"\']+["\'].*requests.*\.(get|post)\(',
        "Avoid allowing untrusted user input to dictate server-side requests, as this can lead to SSRF attacks.",
        "Critical",
        """Validate and sanitize user input before using it in server-side requests.
        Example:
        import requests
    
        # Safe way: Validate URL before making the request
        target_url = user_input.strip()
        if target_url.startswith("https://") or target_url.startswith("http://"):
        response = requests.get(target_url)  # Safe request
        else:
            raise ValueError("Invalid URL")
        """
    ),


])

# Commit changes and close connection
conn.commit()
conn.close()