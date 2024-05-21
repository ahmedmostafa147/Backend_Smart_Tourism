from fastapi.requests import Request
from sqlalchemy import select
from database import get_db, engine
from models import User
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from schemas import UserRegistration, UserLogin, UserUpdate
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import secrets

SECRET_KEY = "d38b291ccebc18af95d4df97a0a98f9bb9eea3c820e771096fa1c5e3a58f3d53"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()

def hash_password(password: str):
    return password_context.hash(password)

def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_token(db: Session, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            return None
        user = db.query(User).filter(User.user_email == user_email).first()
        return user
    except JWTError:
        return None
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = get_user_from_token(db, token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

@router.post("/register")
def register(user: UserRegistration, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.user_email == user.user_email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = User(
        first_name=user.first_name,
        last_name=user.last_name,
        user_password=hash_password(user.user_password),
        user_email=user.user_email,
        user_location=user.user_location
    )
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    user_db = db.query(User).filter(User.user_email == user.user_email).first()
    if not user_db or not verify_password(user.user_password, user_db.user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user_db.user_email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.delete("/delete")
def delete_account(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.delete(current_user)
    db.commit()
    return {"message": "User deleted successfully"}

@router.put("/update")
def update_account(updated_user: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.first_name = updated_user.first_name
    current_user.last_name = updated_user.last_name
    current_user.user_location = updated_user.user_location
    db.commit()
    return {"message": "User updated successfully"}

@router.put("/reset_password")
def reset_password(user_identifier: str, new_password: str, db: Session = Depends(get_db)):
    hashed_password = hash_password(new_password)
    if '@' in user_identifier:
        user = db.query(User).filter(User.user_email == user_identifier).first()
    else:
        user = db.query(User).filter(User.user_id == int(user_identifier)).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.user_password = hashed_password
    db.commit()
    return {"message": "Password reset successfully"}

@router.put("/change_password")
async def change_password(current_password: str, new_password: str, current_user: str = Depends(get_current_user)):
    try:
        conn = engine.connect()
        query = select([User.user_password]).where(User.user_email == current_user)
        result = conn.execute(query).fetchone()

        if result:
            current_hashed_password = result[0]
            if password_context.verify(current_password, current_hashed_password):
                hashed_new_password = hash_password(new_password)
                conn.execute(User.__table__.update().where(User.user_email == current_user).values(user_password=hashed_new_password))
                return {"message": "Password changed successfully"}
            else:
                raise HTTPException(status_code=400, detail="Invalid current password")
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@router.get("/login_google")
async def login_google(request: Request):
    try:
        state = secrets.token_urlsafe(16)
        request.session['state'] = state
        redirect_uri = request.url_for('google_callback')
        return await OAuth.google.authorize_redirect(request, redirect_uri, state=state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/google_callback")
async def google_callback(request: Request):
    try:
        state = request.session.get('state')
        if state is None:
            raise HTTPException(status_code=400, detail="State parameter missing in session")
        
        token = await OAuth.google.authorize_access_token(request)
        user_info = await OAuth.google.parse_id_token(request, token)

        # Check if the state parameter in the callback matches the one in the session
        if 'state' not in token or token['state'] != state:
            raise HTTPException(status_code=400, detail="State parameter mismatch")

        return {"token": token, "user_info": user_info}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Google OAuth callback error")

@router.get("/protected")
async def protected_endpoint(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.user_email == current_user).first()
        if user:
            return {
                "message": f"Hello, {user.first_name} {user.last_name}. You are authenticated.",
                "user_info": {
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.user_email,
                    "location": user.user_location
                }
            }
        else:
            raise HTTPException(status_code=404, detail="User not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/unprotected")
async def unprotected_endpoint():
    return {"message": "This is an unprotected endpoint."}

@router.post("/logout")
async def logout(current_user: str = Depends(get_current_user)):
    """
ليه ياعم تخرج ما انت منورنا والله!!!!!
    """
    return {"message": "Logout successful"}
