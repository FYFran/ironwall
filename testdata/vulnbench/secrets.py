"""Vulnerability Test 1: Hardcoded Secrets"""
import os

# REAL SECRETS — should all be caught
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jK1lM2nO3pQ4r5S6t"
STRIPE_SECRET = "sk_live_fake_test_key_not_real_1234567890"
SLACK_WEBHOOK = "https://hooks.slack.com/services/TFAKE0000/BFAKE0000/xxxxxxxxxxxxxxxxxxxxxxtest"
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecretkey"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3JxH...real_private_key_material...
-----END RSA PRIVATE KEY-----"""
PASSWORD_HASH = "admin:$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

# False positive — should ideally not flag
EXAMPLE_TOKEN = "your_token_here"
PLACEHOLDER = "sk_test_replace_me"

def connect_to_db():
    password = "SuperSecret123!"
    connection_string = f"postgresql://admin:{password}@localhost/production"
    return connection_string
