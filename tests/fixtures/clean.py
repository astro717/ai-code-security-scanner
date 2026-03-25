# clean.py — fixture file for Python scanner integration tests.
# Each snippet is the safe equivalent of a pattern the scanner targets.
# The scanner should produce zero findings for this file.

import os
import subprocess
import hashlib
import requests

# Safe SQL: parameterised query — no injection risk
def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cursor.fetchall()

# Safe subprocess: no shell=True, list form
def run_cmd(program, args):
    subprocess.run([program] + args, check=True)

# Safe eval alternative: ast.literal_eval for data only
import ast
def parse_literal(expr):
    return ast.literal_eval(expr)

# Safe hashing: SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Safe file read: sanitise the path first
def read_file(filename):
    safe_name = os.path.basename(filename)
    with open(os.path.join("/var/data", safe_name)) as f:
        return f.read()

# Safe HTTP: hardcoded trusted URL, no user input
def fetch_health():
    return requests.get("https://api.example.com/health", timeout=5)
