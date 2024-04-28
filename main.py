from fastapi import FastAPI, HTTPException, status, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, MetaData, select, Table, Column, Integer, String, ForeignKey, Boolean, DateTime
from passlib.context import CryptContext
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from typing import List, Optional
from datetime import timezone
import jwt
import random
import asyncio
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from fastapi_session import Session
import secrets
from datetime import datetime


load_dotenv()

app = FastAPI()

SECRET_KEY = "d38b291ccebc18af95d4df97a0a98f9bb9eea3c820e771096fa1c5e3a58f3d53"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
from starlette.middleware.sessions import SessionMiddleware

app.add_middleware(SessionMiddleware, secret_key="8c87d814d4be0ddc08364247da359a61941957e84f62f3cd0e87eb5d853a4144")


DATABASE_URL = "mssql+pyodbc://db_aa8202_tourism_admin:ABCD1234@SQL5113.site4now.net/db_aa8202_tourism?driver=ODBC+Driver+17+for+SQL+Server"
engine = create_engine(DATABASE_URL)
metadata = MetaData()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

users = Table(
    "users",
    metadata,
    Column("user_id", Integer, primary_key=True, index=True),
    Column("first_name", String(length=255)),
    Column("last_name", String(length=255)),
    Column("user_email", String),
    Column("user_password", String),
    Column("user_location", String),
)

metadata.create_all(bind=engine)


def query_database(country: str, governorate: str, category: str, name: str) -> List[str]:
    return []


class UserRegistration(BaseModel):
    first_name: str
    last_name: str
    user_password: str
    user_email: EmailStr
    user_location: Optional[str] = None

class UserLogin(BaseModel):
    user_email: EmailStr
    user_password: str


class UserUpdate(BaseModel):
    first_name: str
    last_name: str
    user_location: str

oauth = OAuth()
oauth.register(
    name='google',
    client_id='661608121084-ujv3v7ptoc1dtr1mp7hegarnrtfsceas.apps.googleusercontent.com',
    client_secret='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',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'scope': 'openid email profile'},
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    userinfo_url='https://openidconnect.googleapis.com/v1/userinfo',
    userinfo_params=None,
    client_kwargs={
        'token_endpoint_auth_method': 'client_secret_post',
        'prompt': 'consent',
        'response_type': 'code id_token',
        'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'
    }
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return password_context.hash(password)


def verify_user_credentials(user_email: str, user_password: str):
    conn = engine.connect()
    query = select(users.c.user_email, users.c.user_password).where(users.c.user_email == user_email)
    result = conn.execute(query).fetchone()

    if result and password_context.verify(user_password, result[1]):
        return True
    return False


def register_user(user: UserRegistration):
    conn = engine.connect()
    conn.execute(users.insert().values(
        first_name=user.first_name,
        last_name=user.last_name,
        user_password=hash_password(user.user_password),
        user_email=user.user_email,
        user_location=user.user_location,
    ))
    conn.commit()


def delete_user(user_email: str):
    conn = engine.connect()
    conn.execute(users.delete().where(users.c.user_email == user_email))
    conn.commit()


def update_user(user_email: str, updated_user: UserUpdate):
    conn = engine.connect()
    conn.execute(users.update().where(users.c.user_email == user_email).values(
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        user_location=updated_user.user_location,
    ))
    conn.commit()


UTC = timezone.utc
def create_access_token(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            return None
        return user_email
    except jwt.JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_email
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
@app.post("/register")
async def register(user: UserRegistration):
    conn = engine.connect()
    query = select(users.c.user_email).where(users.c.user_email == user.user_email)
    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        raise HTTPException(status_code=400, detail="User with this email already registered")

    register_user(user)
    return {"message": "Registration successful"}

@app.post("/login")
async def login(user: UserLogin):
    user_email = user.user_email
    user_password = user.user_password

    if not verify_user_credentials(user_email, user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user_email})
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}


@app.delete("/delete")
async def delete(current_user: str = Depends(get_current_user)):
    delete_user(current_user)
    return {"message": "User deleted successfully"}


@app.put("/update")
async def update(updated_user: UserUpdate, current_user: str = Depends(get_current_user)):
    update_user(current_user, updated_user)
    return {"message": "User updated successfully"}


@app.put("/reset_password")
async def reset_password(user_identifier: str, new_password: str):
    conn = engine.connect()
    hashed_password = hash_password(new_password)
    if '@' in user_identifier:
        conn.execute(users.update().where(users.c.user_email == user_identifier).values(
            user_password=hashed_password
        ))
    else:
        conn.execute(users.update().where(users.c.user_id == int(user_identifier)).values(
            user_password=hashed_password
        ))
    conn.commit()
    return {"message": "Password reset successful"}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

recent_searches = []

class RecentSearch(Base):
    __tablename__ = 'recent_searches'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    country = Column(String)
    governorate = Column(String)
    category = Column(String)
    name = Column(String)

@app.post("/search")
async def search(
    country: str,
    governorate: str,
    category: str,
    name: str,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.user_email == current_user).first()
    if user:
        recent_search = RecentSearch(
            user_id=user.user_id,
            country=country,
            governorate=governorate,
            category=category,
            name=name
        )
        db.add(recent_search)

        recent_search_count = db.query(RecentSearch).filter(RecentSearch.user_id == user.user_id).count()

        if recent_search_count > 10:
            oldest_searches = db.query(RecentSearch).filter(RecentSearch.user_id == user.user_id).order_by(RecentSearch.id.asc()).limit(recent_search_count - 10).all()
            for search in oldest_searches:
                db.delete(search)

        db.commit()

        search_results = query_database(country, governorate, category, name)
        return {"results": search_results}
    else:
        return {"message": "User not found."}

@app.get("/recent_searches")
async def get_recent_searches(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_email == current_user).first()
    if user:
        recent_searches = db.query(RecentSearch).filter(RecentSearch.user_id == user.user_id).order_by(RecentSearch.id.desc()).limit(10).all()
        return {"recent_searches": recent_searches}
    else:
        return {"message": "User not found."}





@app.put("/change_password")
async def change_password(current_password: str, new_password: str, current_user: str = Depends(get_current_user)):
    conn = engine.connect()
    query = select(users.c.user_password).where(users.c.user_email == current_user)
    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        current_hashed_password = result[0]
        if password_context.verify(current_password, current_hashed_password):
            hashed_new_password = hash_password(new_password)
            conn = engine.connect()
            conn.execute(users.update().where(users.c.user_email == current_user).values(
                user_password=hashed_new_password
            ))
            conn.close()
            return {"message": "Password changed successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



@app.get("/login_google")
async def login_google(request: Request):
    state = secrets.token_urlsafe(16)
    request.session['state'] = state
    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state)


@app.get("/google_callback")
async def google_callback(request: Request):
    try:
        state = request.session.get('state')
        if state is None:
            raise HTTPException(status_code=400, detail="State parameter missing in session")
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.parse_id_token(request, token)

        # Check if the state parameter in the callback matches the one in the session
        if 'state' not in token or token['state'] != state:
            raise HTTPException(status_code=400, detail="State parameter mismatch")

        return {"token": token, "user_info": user_info}
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Google OAuth callback error: {e}")
        raise HTTPException(status_code=400, detail="Google OAuth callback error")





items_of_interest = ["restaurants", "hotels", "tours", "archaeological tourism", "for fun", "museum",
                     "water places", "games", "religious tourism", "malls", "parks", "natural views"]
@app.get("/may liked it")
async def get_recommended_items(current_user: str = Depends(get_current_user)):
    # Your existing code...
    recommended_items = random.sample(items_of_interest, min(3, len(items_of_interest)))
    return {"user_id": current_user, "recommended_items": recommended_items}
@app.post("/logout")
async def logout(current_user: str = Depends(get_current_user)):
    """
ليه ياعم تخرج ما انت منورنا والله!!!!!
    """
    return {"message": "Logout successful"}

class Notification(BaseModel):
    user_email: str
    message: str

user_notifications = {}

def send_notification(notification: Notification):
    print(f"Sending notification to user {notification.user_email}: {notification.message}")
    if notification.user_email not in user_notifications:
        user_notifications[notification.user_email] = []
    user_notifications[notification.user_email].append(notification.message)

async def schedule_notifications():
    while True:

        await asyncio.sleep(24 * 3600)
        for user_email, message in user_notifications.items():
            notification = Notification(user_email=user_email, message=message)
            send_notification(notification)

@app.get("/send_notification")
async def send_notification_endpoint(user_email: str, background_tasks: BackgroundTasks):
    default_message = "Reminder: Don't forget to use our app!"
    notification = Notification(user_email=user_email, message=default_message)
    background_tasks.add_task(send_notification, notification)
    return {"detail": "Notification scheduled successfully"}
# -----------------------------------------------------------------


# Define other tables using declarative syntax
# Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    user_email = Column(String(255), nullable=False)
    user_password = Column(String(255), nullable=False)
    user_location = Column(String(255))
    user_favs = relationship("UserFavorite", back_populates="user")
    plans = relationship("UserPlan", back_populates="user")


class Plan(Base):
    __tablename__ = 'plans'
    plan_id = Column(Integer, primary_key=True)
    plan_budget = Column(Integer, nullable=False)
    plan_review = Column(String(255))
    plan_duration = Column(Integer, nullable=False)
    destination = Column(String(50), nullable=False)
    plan_is_recommended = Column(Boolean, nullable=False)

    users = relationship("UserPlan", back_populates="plan")



class Place(Base):
    __tablename__ = 'places'
    place_id = Column(Integer, primary_key=True)
    place_name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False)
    favorite = Column(Boolean)
    gps = Column(String(255), nullable=False)
    place_loc = Column(String(255), nullable=False)
    place_image = Column(String(255), nullable=False)
    rate = Column(Integer)

class Hotel(Base):
    __tablename__ = 'hotels'
    hotel_id = Column(Integer, primary_key=True)
    hotel_name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False)
    favorite = Column(Boolean)
    gps = Column(String(255), nullable=False)
    hotel_loc = Column(String(255), nullable=False)
    hotel_image = Column(String(255), nullable=False)
    rate = Column(Integer)
    hotel_type = Column(String)

class Restaurant(Base):
    __tablename__ = 'restaurants'
    rest_id = Column(Integer, primary_key=True)
    rest_name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False)
    favorite = Column(Boolean)
    gps = Column(String(255), nullable=False)
    rest_loc = Column(String(255), nullable=False)
    rest_image = Column(String(255), nullable=False)
    rate = Column(Integer)
    rest_type = Column(String)

class UserPlan(Base):
    __tablename__ = 'user_plan'
    history_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    plan_id = Column(Integer, ForeignKey('plans.plan_id'))
    timestamp = Column(DateTime, nullable=False, default=datetime.now())
    user = relationship("User", back_populates="plans")
    plan = relationship("Plan", back_populates="users")

# Define association tables
plan_place = Table('plan_place', Base.metadata,
    Column('plan_id', Integer, ForeignKey('plans.plan_id')),
    Column('place_id', Integer, ForeignKey('places.place_id'))
)

plan_hotel = Table('plan_hotel', Base.metadata,
    Column('plan_id', Integer, ForeignKey('plans.plan_id')),
    Column('hotel_id', Integer, ForeignKey('hotels.hotel_id'))
)

plan_restaurant = Table('plan_restaurant', Base.metadata,
    Column('plan_id', Integer, ForeignKey('plans.plan_id')),
    Column('rest_id', Integer, ForeignKey('restaurants.rest_id'))
)

# Define request models
class PlanCreate(BaseModel):
    plan_budget: int
    plan_review: str = None
    plan_duration: int
    destination: str
    plan_is_recommended: bool
    places: list = []
    hotels: list = []
    restaurants: list = []

class Favorite(Base):
        __tablename__ = "favorites"
        fav_id = Column(Integer, primary_key=True, index=True)
        type = Column(String, nullable=False)
        name = Column(String, nullable=False)
        location = Column(String)
        user_favs = relationship("UserFavorite", back_populates="favorite")

class UserFavorite(Base):
        __tablename__ = "user_fav"
        user_id = Column(Integer, ForeignKey("users.user_id"), primary_key=True)
        fav_id = Column(Integer, ForeignKey("favorites.fav_id"), primary_key=True)
        user = relationship("User", back_populates="user_favs")
        favorite = relationship("Favorite", back_populates="user_favs")

    # Create tables
Base.metadata.create_all(bind=engine)

    # CRUD operations
def create_favorite(db: Session, user_id: int, type: str, name: str, location: str):
        db_favorite = Favorite(type=type, name=name, location=location)
        db.add(db_favorite)
        db.commit()
        db.refresh(db_favorite)
        return db_favorite

def delete_favorite(db: Session, fav_id: int):
        db_favorite = db.query(Favorite).filter(Favorite.fav_id == fav_id).first()
        if db_favorite:
            db.delete(db_favorite)
            db.commit()
            return {"message": "Favorite deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Favorite not found")

# Database session setup
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
@app.post("/create_plan")
async def create_plan(plan_data: PlanCreate, current_user: str = Depends(get_current_user)):
    """
    Create a plan for the current user.
    """
    db = SessionLocal()
    try:
        # Fetch user details based on the current user's email
        user = db.query(User).filter(User.user_email == current_user).first()
        if user:
            # Create Plan instance
            plan = Plan(
                plan_budget=plan_data.plan_budget,
                plan_review=plan_data.plan_review,
                plan_duration=plan_data.plan_duration,
                destination=plan_data.destination,
                plan_is_recommended=plan_data.plan_is_recommended
            )
            db.add(plan)
            db.flush()  # This ensures plan_id is populated

            # Associate the user_id with the plan
            user_plan = UserPlan(user_id=user.user_id, plan_id=plan.plan_id)
            db.add(user_plan)

            # Add places to plan
            for place_id in plan_data.places:
                db.execute(plan_place.insert().values(plan_id=plan.plan_id, place_id=place_id))

            # Add hotels to plan
            for hotel_id in plan_data.hotels:
                db.execute(plan_hotel.insert().values(plan_id=plan.plan_id, hotel_id=hotel_id))

            # Add restaurants to plan
            for rest_id in plan_data.restaurants:
                db.execute(plan_restaurant.insert().values(plan_id=plan.plan_id, rest_id=rest_id))

            db.commit()
            return {"message": "Plan created successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create plan: {e}")
    finally:
        db.close()

@app.get("/user_plans")
async def user_plans(current_user: str = Depends(get_current_user)):
    """
    Retrieve plans for the current user.
    """
    db = SessionLocal()
    try:
        # Fetch user details based on the current user's email
        user = db.query(User).filter(User.user_email == current_user).first()
        if user:
            user_plans = db.query(UserPlan).join(Plan).filter(UserPlan.user_id == user.user_id).all()
            return user_plans
        else:
            raise HTTPException(status_code=404, detail="User not found")
    finally:
        db.close()


@app.get("/plan_history/")
async def plan_history():
    db = SessionLocal()
    try:
        plans = db.query(UserPlan).all()
        return plans
    finally:
        db.close()
from typing import List
class FavoriteCreate(BaseModel):
    type: str
    name: str
    location: str
@app.post("/favorites/")
def create_favorite_endpoint(
    favorite_data: FavoriteCreate,
    current_user_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a favorite for the current user.
    """
    try:
        # Fetch user details based on the current user's email
        user = db.query(User).filter(User.user_email == current_user_email).first()
        if user:
            # Create the favorite using the provided data
            favorite = create_favorite(
                db=db,
                user_id=user.user_id,
                **favorite_data.dict()
            )
            return favorite
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create favorite: {e}")

@app.delete("/favorites/")
def delete_favorite_endpoint(
    fav_id: int,
    current_user_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a favorite for the current user.
    """
    try:
        # Fetch user details based on the current user's email
        user = db.query(User).filter(User.user_email == current_user_email).first()
        if user:
            # Delete the favorite
            result = delete_favorite(db=db, fav_id=fav_id)
            return result
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete favorite: {e}")


# -------------------------------------------------------------------------
class SurveyResponse(BaseModel):
    category: str

# SQLAlchemy models
class Survey(Base):
    __tablename__ = "surveys"
    survey_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)

class Option(Base):
    __tablename__ = "options"
    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, index=True)
    survey_id = Column(Integer, ForeignKey("surveys.survey_id"))

@app.post("/survey/")
async def survey(survey_response: SurveyResponse, current_user_email: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        # Fetch user ID based on the current user's email
        user = db.query(User).filter(User.user_email == current_user_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Create survey entry
        survey = Survey(user_id=user.user_id)  # Using the current user's ID obtained from the database
        db.add(survey)
        db.commit()
        db.refresh(survey)

        # Create option entry
        option = Option(category=survey_response.category, survey_id=survey.survey_id)
        db.add(option)
        db.commit()
        db.refresh(option)

        return {"message": "Survey submitted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        db.close()


@app.get("/protected")
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
            return {"message": "User not found."}
    except SQLAlchemyError as e:
        return {"message": f"Database error: {str(e)}"}

@app.get("/unprotected")
async def unprotected_endpoint():

    return {"message": "This endpoint is accessible without authentication."}
