"""Smoke test file for ironwall Python scanning."""
import sqlite3

DB_PASSWORD = "admin123"  # Should be flagged as hardcoded credential

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
    conn = sqlite3.connect("app.db")
    return conn.execute(query).fetchall()

API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"  # Should be flagged as hardcoded secret
