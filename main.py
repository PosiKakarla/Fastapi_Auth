from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import jwt
import hashlib # Standard Python library, no 72-byte limit bug!

app = FastAPI()

# 1. NEW HASHING LOGIC (Replacing the broken bcrypt)
def get_password_hash(password: str):
    # This creates a unique signature of your password
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str):
    return get_password_hash(plain_password) == hashed_password

# 2. DATABASE & SETTINGS
users_db = {}
SECRET_KEY = "MY_SUPER_SECRET_KEY"
ALGORITHM = "HS256"

class UserSchema(BaseModel):
    username: str
    password: str

# 3. ROUTES
@app.get("/")
def home():
    return {"message": "The club is open!"}

@app.post("/register")
def register(user: UserSchema):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash using our new stable function
    hashed = get_password_hash(user.password)
    users_db[user.username] = {"username": user.username, "password": hashed}
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: UserSchema):
    user_in_db = users_db.get(user.username)
    
    # Check if user exists AND if password matches
    if not user_in_db or not verify_password(user.password, user_in_db["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create the Token
    expiration = datetime.now(timezone.utc) + timedelta(minutes=30)
    badge_data = {"sub": user.username, "exp": expiration}
    token = jwt.encode(badge_data, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": token, "token_type": "bearer"}