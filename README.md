**Vulnerable Code Scanner**

A Python-based web application for detecting common OWASP Top 10 vulnerabilities in source code.

**1) Overview**

Vulnerable Code Scanner is a security and educational focused application that analyzes Python source code for potentially vulnerable patterns and presents the findings through a web interface.

The project was built to explore practical application security concepts, vulnerability detection, and secure coding practices while combining a Python backend with a database of vulnerability patterns.

**2) Features**

* Python source-code vulnerability scanning
* Detection of common OWASP Top 10 vulnerability patterns
* Web-based interface for submitting code for analysis
* Local vulnerability database using SQLite
* Vulnerability findings presented through the application interface
* Python-based backend for processing scan requests

**3) How It Works**

User
 ↓
Web Interface
 ↓
Python Backend
 ↓
Code Analysis
 ↓
Vulnerability Pattern Matching
 ↓
SQLite Vulnerability Database
 ↓
Scan Results

**4) Tech Stack**

* Backend: Python
* Web: Flask
* Database: SQLite
* Frontend: HTML, CSS, JavaScript

**5) Project Structure**

Vulnerable-Code-Scanner/
├── backend.py
├── sqlite.py
├── vulnerabilities.db
├── templates/
├── static/
└── README.md

**6) Getting Started**

Prerequisites

* Python 3
* pip

**7) Installation**

Clone this repository.

Install the required dependencies:

pip install -r requirements.txt

Run the Application

Start the backend:

python backend.py

Then open the application in your browser using the local address provided by Flask.

**8) Project Status**

Completed

This project was built as a practical exploration of Python application development, static code analysis, vulnerability detection, and OWASP security concepts.

**9) Disclaimer**

The results produced by this tool may be incomplete, inaccurate, or contain false positives/false negatives. Do not rely solely on this tool to determine whether a system or application is secure.

It is intended to help users understand potential security weaknesses in code and systems, but it is not a replacement for professional vulnerability scanners, SAST/DAST tools, penetration testing, code review, or other established security assessment methods.

