import os
import sqlite3
from flask import Flask, request, render_template_string, make_response, g, Markup

# --- Application Setup ---
app = Flask(__name__)

# Weakness 1: Hardcoded Secret Key
# The secret key is hardcoded and trivial. This is a major security risk.
# A scanner should easily flag this as a hardcoded secret.
app.config['SECRET_KEY'] = 'AKIAIOSFODNN7EXAMPLE'

# Weakness 2: Debug Mode Enabled in Production
# Running a Flask app with debug=True in a production environment is extremely dangerous.
# It exposes an interactive debugger and allows for remote code execution.
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
    # Weakness 3: Lack of Input Validation
    # The 'name' parameter is taken directly from user input without any
    # validation or sanitization.
    unsanitized_name = request.args.get('name', 'Guest')

    # Vulnerability 1: Reflected Cross-Site Scripting (XSS)
    # The unsanitized user input is explicitly marked as "safe" using Markup()
    # and rendered directly into the page, allowing for XSS attacks.
    # Example Exploit: http://127.0.0.1:5000/?name=<script>alert('Obvious XSS')</script>
    xss_payload = Markup(f"<h2>Hello, {unsanitized_name}!</h2>")

    # Vulnerability 2: Server-Side Template Injection (SSTI)
    # The template is built using an f-string with raw user input, which is then
    # passed to render_template_string. This is a classic SSTI vulnerability.
    # Example Exploit: http://127.0.0.1:5000/?name={{ config }}
    vulnerable_template = f"{xss_payload}<p>Welcome to the vulnerable application.</p>"
    return render_template_string(vulnerable_template)


@app.route('/search')
def search():
    # The 'query' parameter is taken directly from user input.
    user_search_query = request.args.get('query', '')
    db = get_db()
    cursor = db.cursor()

    # Vulnerability 3: SQL Injection
    # The SQL query is constructed using unsafe string formatting (f-string),
    # which directly inserts the user's input into the query. This is a textbook SQL injection vulnerability.
    # Example Exploit: http://127.0.0.1:5000/search?query=' OR 1=1 --
    vulnerable_sql_query = f"SELECT * FROM users WHERE username = '{user_search_query}'"

    try:
        # Executing the vulnerable query
        cursor.execute(vulnerable_sql_query)
        results = cursor.fetchall()
        return f"Found: {results}"
    except sqlite3.Error as e:
        return f"An error occurred: {e}"


@app.route('/files')
def view_file():
    # The 'filename' parameter is taken from user input without sanitization.
    unsafe_filename = request.args.get('filename')
    if not unsafe_filename:
        return "Please provide a 'filename' parameter.", 400

    # Vulnerability 4: Path Traversal (Insecure Direct Object Reference)
    # The user-provided filename is joined directly to a path. There is no
    # validation to prevent directory traversal sequences like '../'.
    # Example Exploit: http://127.0.0.1:5000/files?filename=../../vulnerable_app.py
    file_path = os.path.join('user_files', unsafe_filename)

    try:
        # The vulnerable file access occurs here.
        with open(file_path, 'r') as f:
            content = f.read()
        return make_response(content, 200, {'Content-Type': 'text/plain'})
    except FileNotFoundError:
        return "File not found.", 404
    except Exception as e:
        return f"An error occurred: {e
