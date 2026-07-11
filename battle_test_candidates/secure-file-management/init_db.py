from app import create_app

app = create_app()

with app.app_context():
    from app import db  # Import db within the app context
    from app.models import User  # Import User model after db is initialized
    db.create_all()
    print("Database initialized!")
