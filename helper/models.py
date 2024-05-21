from datetime import datetime
from sqlalchemy.orm import relationship
from data.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Table
from datetime import datetime
from sqlalchemy.orm import relationship
from data.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Table

class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(length=255))
    last_name = Column(String(length=255))
    user_email = Column(String, unique=True, index=True)
    user_password = Column(String)
    user_location = Column(String, nullable=True)
    
class RecentSearch(Base):
    __tablename__ = 'recent_searches'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    country = Column(String)
    governorate = Column(String)
    category = Column(String)
    name = Column(String)
# class ForUser(Base):
#     __tablename__ = 'ForUser'
#     user_id = Column(Integer, ForeignKey('users.user_id'), primary_key=True)
#     first_name = Column(String(255), nullable=False)
#     last_name = Column(String(255), nullable=False)
#     user_email = Column(String(255), nullable=False)
#     user_password = Column(String(255), nullable=False)
#     user_location = Column(String(255))
#     plans = relationship("UserPlan", back_populates="user")



# class Notification(Base):
#     __tablename__ = 'notifications'
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey('users.user_id'))
#     message = Column(String)


# class Plan(Base):
#     __tablename__ = 'plans'
#     plan_id = Column(Integer, primary_key=True)
#     plan_budget = Column(Integer, nullable=False)
#     plan_review = Column(String(255))
#     plan_duration = Column(Integer, nullable=False)
#     destination = Column(String(50), nullable=False)
#     plan_is_recommended = Column(Boolean, nullable=False)
#     users = relationship("UserPlan", back_populates="plan")

# class Place(Base):
#     __tablename__ = 'places'
#     place_id = Column(Integer, primary_key=True)
#     place_name = Column(String(255), nullable=False)
#     price = Column(Integer, nullable=False)
#     gps = Column(String(255), nullable=False)
#     place_loc = Column(String(255), nullable=False)
#     place_image = Column(String(255), nullable=False)
#     rate = Column(Integer)

# class Hotel(Base):
#     __tablename__ = 'hotels'
#     hotel_id = Column(Integer, primary_key=True)
#     hotel_name = Column(String(255), nullable=False)
#     price = Column(Integer, nullable=False)
#     gps = Column(String(255), nullable=False)
#     hotel_loc = Column(String(255), nullable=False)
#     hotel_image = Column(String(255), nullable=False)
#     rate = Column(Integer)
#     hotel_type = Column(String)

# class Restaurant(Base):
#     __tablename__ = 'restaurants'
#     rest_id = Column(Integer, primary_key=True)
#     rest_name = Column(String(255), nullable=False)
#     price = Column(Integer, nullable=False)
#     gps = Column(String(255), nullable=False)
#     rest_loc = Column(String(255), nullable=False)
#     rest_image = Column(String(255), nullable=False)
#     rate = Column(Integer)
#     rest_type = Column(String)

# class UserPlan(Base):
#     __tablename__ = 'user_plan'
#     history_id = Column(Integer, primary_key=True)
#     user_id = Column(Integer, ForeignKey('ForUser.user_id'))  # ForeignKey points to ForUser.user_id
#     plan_id = Column(Integer, ForeignKey('plans.plan_id'))
#     timestamp = Column(DateTime, nullable=False, default=datetime.now())



# plan_place = Table('plan_place', Base.metadata,
#     Column('plan_id', Integer, ForeignKey('plans.plan_id')),
#     Column('place_id', Integer, ForeignKey('places.place_id'))
# )

# plan_hotel = Table('plan_hotel', Base.metadata,
#     Column('plan_id', Integer, ForeignKey('plans.plan_id')),
#     Column('hotel_id', Integer, ForeignKey('hotels.hotel_id'))
# )

# plan_restaurant = Table('plan_restaurant', Base.metadata,
#     Column('plan_id', Integer, ForeignKey('plans.plan_id')),
#     Column('rest_id', Integer, ForeignKey('restaurants.rest_id'))
# )

# class Survey(Base):
#     __tablename__ = "surveys"
#     survey_id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer)

# class Option(Base):
#     __tablename__ = "options"
#     id = Column(Integer, primary_key=True, index=True)
#     category = Column(String, index=True)
#     survey_id = Column(Integer, ForeignKey("surveys.survey_id"))
    