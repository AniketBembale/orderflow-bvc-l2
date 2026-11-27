# OrderFlow: Authentication module
# Handles token creation, verification, and the login endpoint.

from datetime import datetime, timedelta,timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration (do not modify)

SECRET_KEY = "orderflow-secret-key-do-not-use-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(prefix="/auth", tags=["auth"])

# Simulated user store — passwords are bcrypt hash of "secret"
USERS_DB = {
    "alice@orderflow.com": {
        "email": "alice@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "admin",
    },
    "bob@orderflow.com": {
        "email": "bob@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "viewer",
    },
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Pydantic models (do not modify)

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    email: str
    role: str


# Helper utilities (do not modify)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_user(email: str) -> Optional[dict]:
    """Return the user dict from USERS_DB or None if not found."""
    return USERS_DB.get(email)


# TODO 1: Generate a signed access token for an authenticated user.
# Accept the user data to embed and an optional expiry window.
# Fall back to the default expiry (30 minutes) if none is provided.
def create_access_token(data:dict,expires_delta:Optional[timedelta]=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(tz=timezone.utc)+expires_delta
    else:
        expire = datetime.now(tz=timezone.utc)+ timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp":expire})
    encode_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)

    return encode_jwt


# TODO 2: Verify an incoming token and extract the user identity from it.
# Reject anything that is expired, tampered with, or missing the user email.
# Return the email and role so the rest of the app knows who is making the request.

def get_current_user_from_token(token:str) -> User:
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=ALGORITHM)
        email:str = payload.get("sub")

        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid token",
                                headers={"WW-Authentication":"Bearer"})

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token",
                            headers={"WW-Authentication":"Bearer"})


    user_data = get_user(email)


    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WW-Authentication":"Bearer"})

    return User(email=user_data["email"],
                role = user_data["role"])

# TODO 3: A reusable auth check that any route can use to protect itself.
# Reads the token from the incoming request, verifies it, and returns the logged-in user.
# Reject the request if the token is invalid or the user no longer exists in the system.


def get_current_user(token:str = Depends(oauth2_scheme))-> User:
    return get_current_user_from_token(token)


# TODO 4: Login endpoint — accepts email and password, issues a signed token on success.
# Check the credentials against the user store and reject invalid combinations.
# On success, return a token the client can use for all subsequent requests.
@router.post("/login",response_model=Token)
def login(form_data : OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)

    if user is None or not verify_password(form_data.password,user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect email or password",
                            headers={"WW-Authentication":"Bearer"})
    
    access_token = create_access_token(data={"sub":user["email"],
                                             "role":user["role"]})

    return {"access_token":access_token,
            "token_type":"Bearer"}