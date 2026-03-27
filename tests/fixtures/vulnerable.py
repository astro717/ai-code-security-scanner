# vulnerable.py — fixture file for Python scanner integration tests.
# Each snippet intentionally triggers a different Python vulnerability detector.
# DO NOT run this code — it is test data only.

import os
import subprocess
import pickle
import hashlib
import requests

user_input = "'; DROP TABLE users; --"

# SQL_INJECTION: string formatting in execute()
def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()

# COMMAND_INJECTION: os.system with variable
def run_cmd(cmd):
    os.system(cmd)

# EVAL_INJECTION: eval() with external input
def evaluate(expr):
    return eval(expr)

# UNSAFE_DESERIALIZATION: pickle.loads with untrusted data
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

# WEAK_CRYPTO: MD5 usage
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# PATH_TRAVERSAL: open() with unsanitised path
def read_file(filename):
    with open("/var/data/" + filename) as f:
        return f.read()

# SSRF: requests.get with user-controlled URL
def fetch_url(url):
    return requests.get(url)

# SSTI: render_template_string with user-controlled template
from flask import render_template_string
def render_page(template):
    return render_template_string(template)

# SECRET_HARDCODED: API key stored as a literal string
api_key = "sk-abcdef1234567890abcdef1234567890"
