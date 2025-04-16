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
        r'\/\b(users?|accounts?|profiles?|orders?)\/(\d+|\{\w+\})\b',
        "Direct object references without access checks",
        "High",
        """Add ownership verification:
        if resource.owner != current_user.id:
            abort(403)"""
    ),

    (
        "Path Traversal",
        r'(?:\.\./|\.\.\\|~/|/etc/passwd)',
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
        r'app\.secret_key\s*=\s*["\'].*["\']',
        "Secrets exposed in code",
        "Critical",
        "Use os.getenv('SECRET_KEY')"
    ),

    (
        "Weak Hash Algorithm",
        r'hashlib\.(md5|sha1)\(',
        "Deprecated hash functions",
        "High",
        "Use 'hashlib.sha256()' for general-purpose hashing or 'bcrypt' for password hashing"
    ),

    #---- 3 Injection ---#
    
    (
        "SQL Injection",
        r'(?:f?"|""").*?(?:SELECT|INSERT|UPDATE|DELETE).*?(?:\{[^}]*\}|\+\s*\w+)',
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
        "Missing Auth Rate Limiting",
        r'@app\.route\(["\'][^"\']*(login|register|reset-password|auth)[^"\']*["\'][^)]*\)[^}]*?def\s+\w+\(\):',
        "Auth endpoints lack rate limiting",
        "High",
        """Add Flask-Limiter:
        @limiter.limit("5/minute")  # Adjust based on use case"""
    ),

    #---- 5 Security Misconfiguration ---#

    (
        "File Disclosure",
        r'open\([^)]*\.(?:py|env|conf|ini)[^)]*\)\.read\(\)',
        "Sensitive file exposure",
        "Critical",
        "Restrict file access or use env vars"
    ),

    #---- 6 Vulnerable Components ---#
    (
        "Known Vulnerable Package",
        r'(flask<2\.0\.0|django<3\.2\.11|requests<2\.26\.0)',
        "Using a package version with known CVEs",
        "Critical",
        "Update to patched version"
    ),

    #---- 7 Authentication Failures ---#
   
    (
        "Missing Login Rate Limiting",
        r'@app\.route\(.*?/login.*?\)[^}]*?if\s+user\s*==\s*None\s*:',
        "Login endpoint lacks rate limiting",
        "High",
        "Use Flask-Limiter: @limiter.limit('5/minute')"
    ),

    (
        "Weak Password Policy",
        r'(?:password|pwd)\s*=\s*["\'][^"\']{0,6}["\']',  # Catches passwords ≤6 chars
        "Short/weak password in code",
        "High",
        """Enforce policies:
        - Min 12 chars
        - Require mixed case + numbers"""
    ),

    #---- 8 Data Integrity ---#
     (
        "Unsafe Deserialization",
        r'(pickle|marshal)\.loads?\(',
        "Arbitrary code execution risk",
        "Critical",
        """Use JSON instead:
        json.loads(safe_data)"""
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
        "No Failed Login Logs",
        r'@app\.route\(.*?/login.*?\)[^}]*?if\s+not\s+user[^}]*?return',
        "Failed login attempts not logged",
        "Medium",
        "Add: logging.warning(f'Failed login for {username}')"
    ),

    #---- 10 SSRF ---#
    (
        "Server-Side Request Forgery",
        r'requests?\.(get|post|put|delete)\([^)]*url\s*=\s*(?!["\'](?:http:\/\/localhost|127\.0\.0\.1))[^)]*\)',
        "Unrestricted external URL fetching",
        "Critical",
        """Validate URLs:
        ALLOWED_DOMAINS = {'trusted.com'}
        if urlparse(url).netloc not in ALLOWED_DOMAINS:
        abort(400)"""
    ),

])

# Commit changes and close connection
conn.commit()
conn.close()
print("Database created succesfully")