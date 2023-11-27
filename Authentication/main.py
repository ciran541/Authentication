from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer
import psycopg2
import time
from pydantic import EmailStr
from jwt import decode
from pydantic import BaseModel
from psycopg2.extras import RealDictCursor
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from schemas import UserCreate, User as UserSchema
from schemas import UserCreate, User  
from database import Base, SessionLocal, engine
from models import User
from security import hash_password, verify_password
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
from typing import Optional
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage



app = FastAPI()

Base.metadata.create_all(bind=engine)

while True:
    try:
        conn = psycopg2.connect(host = 'localhost', database = 'fastapi', user ='postgres' , port='5432',
                            password = 'Ciran@balu20', cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        print("Database connection was succesfull!")
        break
    except Exception as error:
        print("Connecting to database was failed")
        print("Error:", error)   
        time.sleep(5)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

        

# Secret key to sign JWT tokens
SECRET_KEY = "3SBQbr6xqT9B"
ALGORITHM = "HS256"

def generate_reset_token(email: str):
    expires = datetime.utcnow() + timedelta(hours=1)
    
    token_data = {
        "sub": email,
        "exp": expires
    }

    # Create the JWT token
    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

# OAuth2PasswordBearer for handling authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to create a new JWT token
def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Function to get the current user from the token
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return username

    ## route for Superuser 

@app.post("/assign-role/{user_id}/", response_model=dict)
def assign_role(
    user_id: int, 
    role: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check if the current user is a superuser
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Permission denied. Only superusers can assign roles.")

    # Find the user by user_id
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if the specified role is allowed
    allowed_roles = ["admin", "manager", "employee", "user"]
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed roles: {', '.join(allowed_roles)}")

    # Assign the specified role to the user
    user.role = role
    db.commit()

    return {"message": f"Role '{role}' assigned to user {user.username}"}


##  route for Signup/User registration 

@app.post("/signup/")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if the passwords match
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    # Check if the username is already taken
    existing_username = db.query(User).filter(User.username == username).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Check if the email is already registered
    existing_email = db.query(User).filter(User.email == email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password before storing it
    hashed_password = hash_password(password)
    
    # Create a new user
    new_user = User(username=username, email=email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User created successfully"}

## Route for user login and token generation
@app.post("/login/")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password

    # Retrieve user from the database based on the provided username
    user = db.query(User).filter(User.username == username).first()

    # Check if the user exists and if the provided password matches the stored hashed password
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate a JWT token upon successful authentication
    token_data = {"sub": user.username}  # Adjust token data as needed
    token = create_jwt_token(token_data)
    
    return {"access_token": token, "token_type": "bearer"}


# Function to send an email with the reset token
def send_reset_token_email(email_to: EmailStr, reset_token: str):
    # Create a FastMail ConnectionConfig
    conf = ConnectionConfig(
        MAIL_USERNAME="f893fe229f13b2",
        MAIL_PASSWORD="b7bda532f8a57c",
        MAIL_FROM="ciranjivi@gmail.com",
        MAIL_PORT=587,
        MAIL_SERVER="smtp.example.com",
        MAIL_TLS=True,
        MAIL_SSL=False
    )
    
    # Create a FastMail instance
    fm = FastMail(conf)
    
    # Compose the email message
    subject = "Password Reset Request"
    body = f"Your password reset token is: {reset_token}"
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body
    )
    
    # Send the email with the reset token
    fm.send_message(message)

# Route for initiating password reset
@app.post("/forgot-password/")
def forgot_password(email: EmailStr = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        reset_token = create_jwt_token({"sub": user.email})
        send_reset_token_email(email, reset_token)
        return {"message": "Password reset initiated. Check your email for instructions."}
    else:
        raise HTTPException(status_code=404, detail="Email not found")

# Route for resetting password using reset token
@app.post("/reset-password/")
def reset_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if user:
            hashed_password = hash_password(new_password)
            user.password = hashed_password
            db.commit()
            return {"message": "Password reset successfully."}
        else:
            raise HTTPException(status_code=404, detail="Invalid or expired token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    

    
