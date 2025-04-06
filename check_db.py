import sqlite3
conn = sqlite3.connect("vulnerabilities.db")
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Patterns';")
print(cursor.fetchone())  # Should print ('Patterns',) if the table exists
conn.close()
