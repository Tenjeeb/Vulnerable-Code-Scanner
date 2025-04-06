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

    (
        "Missing CSRF Protection",
        r'@app\.route\(.*?methods=\[.*?POST.*?\]\)[^@]*?def\s+\w+\([^)]*\):[^}]*?(request\.(form|json|args)\[',
        "Missing CSRF protection on form handlers",
        "High",
        """Add CSRF protection:
        from flask_wtf.csrf import CSRFProtect
        CSRFProtect(app)"""
    ),

    #---- 2 Cryptographic Failure ---#
    
    (
        "Hardcoded Secret",
        r'(?<!SELECT )(?<!WHERE )(?<!AND )\b(\w+)\s*=\s*["\'][^"\']*(password|secret|key)[^"\']*["\']',
        "Secrets exposed in code (excludes SQL clauses)",
        "Critical",
        "Use os.getenv('SECRET_KEY')"
    ),

    (
        "Weak Hash Algorithm",
        r'hashlib\.(md5|sha1)\(',
        "Deprecated hash functions",
        "High",
        "Use `hashlib.sha256()` or `bcrypt`"
    ),

    #---- 3 Injection ---#
    
    (
        "SQL Injection",
        r'f?"SELECT\b.*WHERE.*\{[^}]*\}.*\{[^}]*\}',
        "Unparameterized query with user input",
        "Critical",
        "Use cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
    ),

    (
        "XSS Risk",
        r'render_template\([^)]*\{[^}]*\}(?!\s*\|\s*(safe|escape|e))',
        "Unescaped variable in template",
        "High",
        "Use {{ user_input|e }} or disable autoescape explicitly"
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
        "Plaintext Password",
        r'(?<!SELECT )(?<!WHERE )(?<!AND )password\s*=\s*["\'][^"\']+["\']',
        "Plaintext password in variable assignment",
        "Critical",
        "Use generate_password_hash()"
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

    (
        "Unsafe YAML",
        r'yaml\.load\([^)]*\)',
        "YAML parsing with code execution",
        "Critical",
        "Use `yaml.safe_load()`"
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
        r'requests?\.(get|post|put|delete)\([^)]*\)',
        "Unrestricted URL fetching",
        "Critical",
        """Validate URLs:
        ALLOWED_DOMAINS = {'trusted.com'}
        if not any(urlparse(url).netloc.endswith(d) for d in ALLOWED_DOMAINS):
            abort(400)"""
    ),

    (
        "XXE Risk",
        r'(xml\.etree\.ElementTree|lxml\.etree)\.(fromstring|parse|iterparse)\(',
        "XML parsing with DTDs enabled",
        "Critical",
        """Disable entities:
        parser = lxml.etree.XMLParser(resolve_entities=False)"""
    )
])

# Commit changes and close connection
conn.commit()
conn.close()
print("Database created succesfully")