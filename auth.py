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
    # Protect against missing/invalid stored hash and bcrypt limitations.
    if not hashed_password:
        return False

    # Bcrypt has a 72 byte input limit; reject overly long passwords early
    try:
        if isinstance(plain_password, str) and len(plain_password.encode("utf-8")) > 72:
            # Do not attempt to verify very long passwords (would raise ValueError in bcrypt)
            return False
    except Exception:
        # If encoding fails for some reason, fall back to verification attempt below
        pass

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, AttributeError, TypeError) as e:
        # These commonly happen when the bcrypt backend isn't available or input is invalid.
        # Log for debugging and return False so callers treat it as authentication failure
        print(f"Password verification error: {e}")
        return False
    except Exception as e:
        # Catch-all to avoid leaking server errors as 500s during auth attempts
        print(f"Unexpected password verification error: {e}")
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
    return verify_password(password, ADMIN_PASSWORD_HASH)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
    