from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  # pre-hashed for "adminpass"

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        # If bcrypt backend is not available or the hash is invalid, return False
        print(f"verify_password error: {e}")
        return False

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_admin(username: str, password: str) -> bool:
    if username != ADMIN_USERNAME:
        return False
    # Prefer verifying against a stored hash, but fall back to plaintext ADMIN_PASSWORD
    if ADMIN_PASSWORD_HASH:
        try:
            if verify_password(password, ADMIN_PASSWORD_HASH):
                return True
        except Exception:
            pass

    # Fallback: plain-text admin password (useful when bcrypt isn't available in the runtime)
    raw = os.getenv("ADMIN_PASSWORD")
    if raw and password == raw:
        return True

    return False

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
    