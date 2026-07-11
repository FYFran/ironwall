import os
from app import create_app

app = create_app()

# Ensure the uploads directory exists
uploads_dir = os.path.join(app.root_path, '../uploads')
os.makedirs(uploads_dir, exist_ok=True)

# Ensure the instance directory exists and is writable
instance_dir = os.path.join(app.root_path, '../instance')
os.makedirs(instance_dir, exist_ok=True)
if not os.access(instance_dir, os.W_OK):
    raise PermissionError(
        f"Instance directory '{instance_dir}' is not writable. Please check permissions.")

# Ensure the database and tables exist
with app.app_context():
    db_path = os.path.join(app.root_path, '../instance/site.db')
    if not os.path.exists(db_path):
        from app import db
        db.create_all()
        print("Database initialized!")

if __name__ == '__main__':
    cert_path = "/etc/letsencrypt/live/sfm.3.149.241.240.sslip.io/fullchain.pem"
    key_path = "/etc/letsencrypt/live/sfm.3.149.241.240.sslip.io/privkey.pem"

    default_cert_path = "certs/cert.pem"
    default_key_path = "certs/key.pem"

    ssl_context = (
        cert_path if os.path.exists(cert_path) else default_cert_path,
        key_path if os.path.exists(key_path) else default_key_path
    )
    app.run(
        debug=True,
        ssl_context=ssl_context,
        host='0.0.0.0',
        port=443
    )
