from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse
import firebase_admin
from firebase_admin import credentials, auth
import pyrebase
from models import LoginSchema, SignUpSchema
import requests

app = FastAPI(
    description="This is the simple Firebase User Authentication",
    title="Firebase Auth"
)

# Firebase initialization
if not firebase_admin._apps:
    cred = credentials.Certificate("serviceAccountKey.json")
    firebase_admin.initialize_app(cred)

firebaseConfig = {
  "apiKey": "AIzaSyDgbJ1wTsY5dUnw8-PTWIX91nuVa2q73TU",
  "authDomain": "fir-auth-96047.firebaseapp.com",
  "projectId": "fir-auth-96047",
  "storageBucket": "fir-auth-96047.appspot.com",
  "messagingSenderId": "656243672150",
  "appId": "1:656243672150:web:a0973879d479abe83d27f7",
  "measurementId": "G-9L6FKJ00TW",
  "databaseURL":""
}

firebase = pyrebase.initialize_app(firebaseConfig)

# Sign-up endpoint
@app.post('/signup')
async def create_an_account(user_data: SignUpSchema):
    email = user_data.email
    password = user_data.password

    try:
        user = auth.create_user(email=email, password=password)
        return JSONResponse(content={"message": "User account created successfully", "user_id": user.uid}, status_code=201)
    except auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail=f"Account already exists for email: {email}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")

# Login endpoint
@app.post('/login')
async def create_access_token(user_data: LoginSchema):
    email = user_data.email
    password = user_data.password

    try:
        user = firebase.auth().sign_in_with_email_and_password(email=email, password=password)
        token = user['idToken']
        return JSONResponse(content={"token": token}, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid credentials")  

# Token validation endpoint
@app.post('/ping')
async def validate_token(token: str):
    try:
        decoded_token = auth.verify_id_token(token)
        return JSONResponse(content={"user_id": decoded_token['uid']}, status_code=200)
    except auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token validation error: {str(e)}")

# Forgot password endpoint
@app.post('/forgot-password')
async def forgot_password(email: str = Body(...)):
    try:
        auth.generate_password_reset_link(email)
        return JSONResponse(content={"message": "Password reset link sent successfully"}, status_code=200)
    except auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forgot password error: {str(e)}")

# Reset password endpoint
@app.post('/reset-password')
async def reset_password(oob_code: str, new_password: str):
    try:
        auth.verify_password_reset_oob(oob_code)
        auth.update_user(auth.get_user_by_password_reset_oob_code(oob_code).uid, password=new_password)
        return JSONResponse(content={"message": "Password reset successful"}, status_code=200)
    except auth.InvalidOobCodeError:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")
    except auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reset password error: {str(e)}")
    

    # Endpoint for Google Sign-In
@app.post('/google-signin')
async def google_signin(token_id: str):
    try:
        # Google Token Validation
        validation_url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token_id}"
        response = requests.get(validation_url)
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google ID token")

        # Verify the Google ID token using Firebase Authentication
        decoded_token = auth.verify_id_token(token_id)
        user_id = decoded_token['uid']

        # Perform additional logic here (e.g., create a user session, return user info)
        return {"user_id": user_id, "message": "Google Sign-In successful"}
    except auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Invalid Google ID token")