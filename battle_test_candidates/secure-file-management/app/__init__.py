from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os
import logging
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # Redirect to login page if not authenticated


def create_app():
    app = Flask(__name__)
    encryption_key = os.getenv('ENCRYPTION_KEY')
    if not encryption_key:
        raise ValueError("No ENCRYPTION_KEY set for Flask application")
    cipher_suite = Fernet(encryption_key)
    app.config['CIPHER_SUITE'] = cipher_suite

    app.secret_key = os.environ['FLASK_SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, '../uploads')

    db.init_app(app)
    login_manager.init_app(app)

    # Import models after initializing extensions
    from .models import User  # Move this import here

    # Import blueprints after initializing extensions
    from .routes import main, auth
    app.register_blueprint(main)
    app.register_blueprint(auth, url_prefix='/auth')

    # ensure the logs directory exists
    if not os.path.exists('logs'):
        os.mkdir('logs')

    # set up a rotating file handler: 10 MB per file, keep 5 backups
    file_handler = RotatingFileHandler(
        filename='logs/app.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    # choose a nice format
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)

    # attach to Flask's logger
    app.logger.addHandler(file_handler)

    # optionally set the overall log level (default is WARNING)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

    return app

@login_manager.user_loader
def load_user(user_id):
    from .models import User
    return User.query.get(int(user_id))
