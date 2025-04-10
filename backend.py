from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import re
import sqlite3

app = Flask(__name__)

# Configuring upload folder and allowed file types
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Helper function to check allowed file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scan_code(file_content):
    vulnerabilities = []
    lines = file_content.splitlines()
    reported_vulnerabilities = set()  # Set to track reported vulnerabilities

    try:
        conn = sqlite3.connect("vulnerabilities.db", check_same_thread=False)
        cursor = conn.cursor()

        # Check if the database is accessible
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Patterns';")
        if not cursor.fetchone():
            print("Error: 'Patterns' table is missing in the database.")
            return [{"error": "Database table 'Patterns' is missing"}]

        # Fetch all patterns from the database
        cursor.execute("SELECT name, pattern, description, severity, secure_example FROM Patterns")
        patterns = cursor.fetchall()

        # Scan each line of the file for vulnerabilities
        for i, line in enumerate(lines):
            for name, pattern, description, severity, secure_example in patterns:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        if (name, i) not in reported_vulnerabilities:
                            line_content = line.strip()
                            print(f"Vulnerability found: {name}, Line {i + 1}, Content: {line_content}")
                            vulnerabilities.append({
                                "type": name,
                                "line": i + 1,
                                "line_content": line_content,
                                "description": description,
                                "severity": severity,
                                "secure_example": secure_example
                            })
                            reported_vulnerabilities.add((name, i))
                except re.error as e:
                    print(f"Regex error in pattern '{name}': {e}")

    except sqlite3.Error as db_error:
        print(f"Database error: {db_error}")
        return [{"error": "Database connection error"}]

    finally:
        conn.close()

    return vulnerabilities


# Route for serving the hTML page
@app.route('/')
def index():
    return render_template('index.html')

# Route for serving the Feedback page
@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

# Route for serving the tutorial page
@app.route('/tutorial')
def tutorial():
    return render_template('tutorial.html')

# Route for serving add_patterns page
@app.route('/add_patterns')
def add_patterns():
    return render_template('add_patterns.html')

#Upload and scan endpoint
@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Read the file
        with open(file_path, 'r') as f:
            file_content = f.read()
            if not file_content.strip():
                return jsonify({"error": "Uploaded file is empty"}), 400

        # Scan for vulnerabilities
        vulnerabilities = scan_code(file_content)
        return jsonify({"vulnerabilities": vulnerabilities, "filename": filename}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
# Run the server
if __name__ == '__main__':
    app.run(debug=True)