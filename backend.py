from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import re
import sqlite3

app = Flask(__name__)

# Configuring upload folder and allowed file types
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Vulnerability detection with database-driven logic
def scan_code(file_content):
    vulnerabilities = []
    lines = file_content.splitlines()
    reported_vulnerabilites = set()   # Set to track reported vulnerabilities
  
    # Connect to SQLite Database
    conn = sqlite3.connect("vulnerabilities.db")
    cursor = conn.cursor()

    # Fetch all patterns from the database
    cursor.execute("Select name, pattern, description, severity, secure_example FROM Patterns")
    patterns = cursor.fetchall()

    # Scan each line of the file for vulnerabilities
    for i, line in enumerate(lines):
        for name, pattern, description, severity, secure_example in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Avoid reporting duplicate vulnerabilites
                if (name, i) not in reported_vulnerabilites:
                    vulnerabilities.append({
                        "type": name,
                        "line": i + 1,
                        "description": description,
                        "severity": severity,
                        "secure_example": secure_example
                })
                reported_vulnerabilites.add((name, i)) 
                 # Mark this vulnerabilities as reported
    conn.close()
    return vulnerabilities

# Route for serving the hTML page
@app.route('/')
def index():
    return render_template('index.html')

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