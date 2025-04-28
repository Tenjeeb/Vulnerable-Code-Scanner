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

# Clear existing data to avoid duplicates
cursor.execute("DELETE FROM Patterns")

# Insert sample data 
cursor.executemany("""
INSERT INTO Patterns (name, pattern, description, severity, secure_example)
VALUES (?, ?, ?, ?, ?)
""", [
    #---- 1 Broken Access Control ---#
    (
        "Path Traversal",
        r'send_file\([^)]*?\+\s*request\.(args|files|form|json)\.[a-z_]+\(',
        "User input used in file paths can expose sensitive files.",
        "Critical",
        """Use secure_filename to sanitize file names:
        from werkzeug.utils import secure_filename
        
        filename = secure_filename(input)
        file_path = os.path.join('uploads', filename)
        return send_file(file_path)"""
    ),

    #---- 2 Cryptographic Failure ---#
    (
        "Hardcoded Secret",
        r'app\.secret_key\s*=\s*["\'].*["\']',
        "Secret keys should not be hardcoded in the source code.",
        "High",
        """Store secrets in environment variables:
        import os
        app.secret_key = os.getenv('SECRET_KEY')"""
    ),

    (
        "Weak Hash Algorithm",
        r'hashlib\.(md5|sha1)\(',
        "MD5 and SHA1 are outdated and insecure for hashing.",
        "High",
        """Use stronger algorithms like SHA-256 or bcrypt:
        import hashlib
        hashlib.sha256(data).hexdigest()
        
        #For passwords:
        # import bcrypt
        # hashes = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"""
    ),

    #---- 3 Injection ---#
    (
        "SQL Injection",
        r'(SELECT|INSERT|UPDATE|DELETE).*?[\'"]\s*\+\s*\w+\s*\+\s*[\'"]',
        "User input is used in SQL query without parameters.",
        "Critical",
        """Use parameterized queries:
        cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"""
    ),

    (
        "XSS Risk",
        r'render_template\([^)]*\{[^}]*\}(?!\s*\|\s*(safe|escape|e))',
        "HTML output is not escaped properly.",
        "High",
        """Escape user input in templates:
        {{ user_input|e }}"""
    ),

    (
        "Command Injection",
        r'subprocess\.\w+\(.*?\{.*?\}.*?,?\s*shell=True',
        "User input in shell command with shell=True is dangerous.",
        "Critical",
        """Avoid shell = True, use argument list:
        subprocess.run(['cmd', 'arg'], shell=False)"""
    ),
    
    (
        "Use of eval()",
        r'\beval\(',
        "Use of eval() can execute arbitrary code and should be avoided.",
        "Critical",
        """Avoid using eval(). If needed, use safer alternatives like ast.literal_eval:
        import ast
        value = ast.literal_eval(user_input)"""
    ),

    #---- 4 Security Misconfiguration ----#
    (
        "Debug Mode Enabled",
        r'app\.debug\s*=\s*True',
        "Debug mode is enabled, which can expose sensitive info in production",
        "High",
        """Disable debug mode:
        app.debug = False
        Or configure using environment variables"""
    ),
  
    #---- 5 Identification and Authentication Failures ---#
    (
        "Use of Hardcoded Credentials",
        r'(password|username)\s*=\s*["\'][^"\']+["\']',
        "Hardcoded username or password detected, risking unathorized access",
        "High",
        """Avoid hardcoding credentials in source code. Use environment variables.
        import os

        username = os.getenv("APP_USERNAME")
        password = os.getenv("APP_PASSWORD") """
    ),

    #---- 6 Software and Data Integrity Failures---#
    (
        "Unsafe Deserialization",
        r'(pickle|marshal)\.loads?\(',
        "Untrusted input in deserialization can lead to code execution.",
        "Critical",
        """Use safe formats like JSON:
        import json
        data = json.loads(safe_input)"""
    ),

    #---- 7 Server-Side Request Forgery (SSRF) ---#
    (
        "Server-Side Request Forgery",
        r'requests?\.(get|post|put|delete)\([^)]*(?:url\s*=|[\w\[\]]+\s*(?:,|\)))',
        "User-controlled URLs can trigger internal requests.",
        "High",
        """Allow only trusted domains:
        from urllib.parse import urlparse

        ALLOWED_DOMAINS = {'trusted.com'}
        if urlparse(url).netloc not in ALLOWED_DOMAINS:
            abort(400)"""
    ),
])

# Commit changes and close connection
conn.commit()
conn.close()
print("Database created succesfully")