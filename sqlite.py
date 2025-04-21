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
        r'send_file\(.*?\+.*?request\.',
        "Unsanitized user input in file path allows directory traversal",
        "Critical",
        """Use secure_filename:
        from werkzeug.utils import secure_filename
        filename = secure_filename(input)"""
    ),

    (
        "Insecure Direct Object Reference (IDOR)",
        r'@app\.route\(.*?/(users?|accounts?|orders?)/(<\w+>|\d+)',
        "Direct object references without access control",
        "High",
        """Add ownership checks:
        if resource.owner_id != current_user.id:
        abort(403)"""
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
      
    #---- 4 Identification and Authentication Failures ---#
    (
        "Weak Password Policy",
        r'(?:password|pwd)\s*=\s*["\'][^"\']{0,6}["\']', 
        "Short/weak password in code",
        "High",
        """Enforce policies:
        - Min 12 chars
        - Require mixed case + numbers"""
    ),

    #---- 5 Software and Data Integrity Failures---#
    (
        "Unsafe Deserialization",
        r'(pickle|marshal)\.loads?\(',
        "Arbitrary code execution risk",
        "Critical",
        """Use JSON instead:
        json.loads(safe_data)"""
    ),

    #---- 6 Server-Side Request Forgery (SSRF) ---#
    (
        "Server-Side Request Forgery",
        r'requests?\.(get|post|put|delete)\([^)]*(?:url\s*=|[\w\[\]]+\s*(?:,|\)))',
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