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
    "IDOR in URLs",
    r'\/\b(users?|accounts?|profiles?|orders?)\/\d+\b',
    "Direct object references without access checks",
    "High",
    """Add ownership verification:
    if resource.owner != current_user.id:
        abort(403)"""
),

(
    "Path Traversal",
    r'(\.\.\/|\.\.\\|\~\/)',
    "Directory traversal possible",
    "Critical",
    """Use secure_filename:
    from werkzeug.utils import secure_filename
    filename = secure_filename(input)"""
),

#---- 2 Cryptographic Failure ---#
(
    "Hardcoded Secrets",
    r'(password|secret|key)\s*=\s*["\'][^\'"]+["\']',
    "Secrets exposed in source code",
    "Critical",
    """Use environment variables:
    import os
    key = os.getenv('SECRET_KEY')"""
),

#---- 3 Injection ---#
(
    "SQL Injection",
    r'execute\(f?["\'].*?\{.*?\}',
    "Unparameterized SQL queries",
    "Critical",
    """Use query parameters:
    cursor.execute("SELECT * FROM users WHERE id=?", (id,))"""
),

(
    "Command Injection",
    r'subprocess\.\w+\(.*?\{.*?\}.*?,?\s*shell=True',
    "Unsafe shell command execution",
    "Critical",
    """Use shell=False:
    subprocess.run(['cmd', 'arg'], shell=False)"""
),

#---- 4 Insecure Design ---#
(
    "Missing Rate Limiting",
    r'@app\.route\(.*?\)\s*def\s+\w+\(\):',
    "No brute-force protection",
    "Medium",
    """Add Flask-Limiter:
    from flask_limiter import Limiter
    limiter = Limiter(app)"""
),

#---- 5 Security Misconfiguration ---#
(
    "Debug Mode Enabled",
    r'app\.run\(.*?debug\s*=\s*True',
    "Debug mode exposes sensitive data",
    "High",
    """Disable in production:
    app.run(debug=False)"""
),

#---- 6 Vulnerable Components ---#
(
    "Outdated Flask",
    r'from flask import|import flask',
    "Update to latest Flask version",
    "High",
    """Check updates:
    pip list --outdated
    pip install --upgrade flask"""
),

#---- 7 Authentication Failures ---#
(
    "Plaintext Passwords",
    r'password\s*=\s*["\'][^\'"]+["\']',
    "Passwords should be hashed",
    "Critical",
    """Use password hashing:
    from werkzeug.security import generate_password_hash
    hash = generate_password_hash(password)"""
),

#---- 8 Data Integrity ---#
(
    "Unsafe Pickle",
    r'pickle\.loads\([^)]*\)',
    "Arbitrary code execution risk",
    "Critical",
    """Use JSON instead:
    import json
    data = json.loads(safe_data)"""
),

#---- 9 Logging Failures ---#
(
    "Sensitive Data in Logs",
    r'logging\.\w+\(.*?(password|secret|key)',
    "Secrets exposed in logs",
    "High",
    """Sanitize logs:
    logging.info("User %s logged in", username)"""
),

#---- 10 SSRF ---#
(
    "Server-Side Request Forgery",
    r'requests\.get\([^)]*\)',
    "Unrestricted URL fetching",
    "Critical",
    """Validate URLs:
    if not url.startswith('https://trusted.com'):
        abort(400)"""
)
])

# Commit changes and close connection
conn.commit()
conn.close()