# crud.py
from sqlalchemy.orm import Session
from .models import User

def create_user(
    db: Session, username: str, email: str, 
    hashed_password: str, role: str, 
    is_superuser: bool = False
):
    db_user = User(
        username=username, email=email, 
        hashed_password=hashed_password, role=role, 
        is_superuser=is_superuser
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
