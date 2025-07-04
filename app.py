import os
import sqlite3
from flask import Flask, request, render_template_string, make_response, g

# --- Application Setup ---
app = Flask(__name__)

# Weakness 1: Hardcoded Secret Key
# The secret key should be a complex, randomly generated value loaded from a
# secure location (like an environment variable or a secrets manager), not hardcoded.
app.config['SECRET_KEY'] = 'this-is-not-a-secret'

# Weakness 2: Debug Mode Enabled
# Running a Flask app with debug=True in a production environment is extremely dangerous.
# It exposes an interactive debugger in the browser if an error occurs,
# allowing an attacker to execute arbitrary Python code on the server.
app.config['DEBUG'] = True

DATABASE = 'database.db'

def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database with some sample data."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, profile TEXT)")
        cursor.execute("INSERT OR IGNORE INTO users (id, username, profile) VALUES (?, ?, ?)", (1, 'admin', 'Administrator account.'))
        cursor.execute("INSERT OR IGNORE INTO users (id, username, profile) VALUES (?, ?, ?)", (2, 'guest', 'Guest account.'))
        db.commit()


# --- Routes and Vulnerabilities ---

@app.route('/')
def home():
    # Vulnerability 1: Cross-Site Scripting (XSS)
    # The 'name' parameter from the URL query string is directly embedded into the HTML template
    # without any sanitization or escaping. An attacker can inject malicious scripts.
    # Example Exploit: http://127.0.0.1:5000/?name=<script>alert('XSS')</script>
    name = request.args.get('name', 'Guest')
    
    # Weakness 3: Lack of Robust Input Validation
    # The application assumes 'name' is a simple string. It doesn't validate its
    # length, character set, or format, making it easier to craft exploit payloads.

    # Vulnerability 2: Server-Side Template Injection (SSTI)
    # The template is created by concatenating a string with user-provided data ('name').
    # Templating engines like Jinja2 (used by Flask) can execute code within {{ ... }}.
    # An attacker can inject template expressions to execute code on the server.
    # Example Exploit: http://127.0.0.1:5000/?name={{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}
    template = f"<h2>Hello, {name}!</h2><p>Welcome to the vulnerable application.</p>"
    return render_template_string(template)


@app.route('/search')
def search():
    # Vulnerability 3: SQL Injection
    # The 'query' parameter is directly concatenated into an SQL statement.
    # This allows an attacker to manipulate the query to bypass authentication,
    # extract sensitive data, or modify the database.
    # Example Exploit: http://127.0.0.1:5000/search?query=' OR 1=1 --
    search_query = request.args.get('query', '')
    db = get_db()
    cursor = db.cursor()
    
    # This is the vulnerable line
    query_string = f"SELECT * FROM users WHERE username = '{search_query}'"
    
    try:
        cursor.execute(query_string)
        results = cursor.fetchall()
        return f"Found: {results}"
    except sqlite3.Error as e:
        return f"An error occurred: {e}"


@app.route('/files')
def view_file():
    # Vulnerability 4: Insecure Direct Object Reference (IDOR) / Path Traversal
    # The 'filename' parameter is used to read a file from the filesystem without
    # validating the path. An attacker can use '..' to navigate the directory
    # structure and read arbitrary files from the server.
    # Example Exploit: http://127.0.0.1:5000/files?filename=../../../../../etc/passwd
    filename = request.args.get('filename')
    if not filename:
        return "Please provide a 'filename' parameter.", 400
    
    try:
        # The vulnerable file access
        with open(os.path.join('user_files', filename), 'r') as f:
            content = f.read()
        return make_response(content, 200, {'Content-Type': 'text/plain'})
    except FileNotFoundError:
        return "File not found.", 404
    except Exception as e:
        return f"An error occurred: {e}", 500


if __name__ == '__main__':
    # Setup for demonstration
    if not os.path.exists('user_files'):
        os.makedirs('user_files')
    with open('user_files/welcome.txt', 'w') as f:
        f.write('This is a safe, intended file.')
    
    init_db()
    
    # To run this app:
    # 1. Make sure you have Flask installed (`pip install Flask`).
    # 2. Save this code as a Python file (e.g., `vulnerable_app.py`).
    # 3. Run it from your terminal (`python vulnerable_app.py`).
    # 4. Access http://127.0.0.1:5000 in your browser and try the exploit examples.
    app.run(host='0.0.0.0', port=5000)
