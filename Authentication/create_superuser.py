from models import User
from database import SessionLocal, engine
from security import hash_password

def create_superuser():
    # Create a superuser
    superuser = User(
        username="admin",
        email="admin@example.com",
        password=hash_password("adminpassword"),
        role="admin",
        is_superuser=True
    )

    # Add the superuser to the database
    db = SessionLocal()
    db.add(superuser)
    db.commit()
    db.refresh(superuser)

    print("Superuser created successfully.")

if __name__ == "__main__":
    create_superuser()
