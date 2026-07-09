"""Vulnerability Test 2: Injection Vulnerabilities"""
import os
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SQL INJECTION — should be caught
@app.route('/user/<username>')
def get_user_bad(username):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()

@app.route('/search')
def search():
    keyword = request.args.get('q')
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    return str(query)

# COMMAND INJECTION — should be caught
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = os.system(f"ping -c 1 {host}")
    return str(result)

@app.route('/exec')
def run_cmd():
    cmd = request.args.get('cmd')
    output = subprocess.check_output(cmd, shell=True)
    return output

@app.route('/eval')
def eval_code():
    code = request.args.get('code')
    return str(eval(code))

# PATH TRAVERSAL — should be caught
@app.route('/download')
def download():
    filename = request.args.get('file')
    path = os.path.join('/var/www/uploads/', filename)
    return open(path).read()

# XSS — should be caught
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return f"<html><body>Hello, {name}!</body></html>"

# INSECURE DESERIALIZATION — should be caught
import pickle
@app.route('/load')
def load_data():
    data = request.args.get('data')
    return str(pickle.loads(data.encode()))

# XXE — should be caught
from xml.etree.ElementTree import parse as xml_parse
@app.route('/xml')
def parse_xml():
    xml_data = request.args.get('xml')
    tree = xml_parse(xml_data)  # vulnerable to XXE
    return str(tree)

if __name__ == '__main__':
    app.run(debug=True)  # debug mode in production
