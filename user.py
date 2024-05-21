import random
from fastapi import APIRouter, Depends
from auth import get_current_user
from sqlalchemy.orm import Session
from fastapi import HTTPException
from database import SessionLocal
from models import ForUser, Survey, Option, Notification,User, UserPlan, Plan, Place, plan_place, Hotel, plan_hotel, Restaurant, plan_restaurant, Survey, Option
import asyncio
from sqlalchemy.exc import SQLAlchemyError
from database import get_db
from schemas import  SurveyResponse, PlanCreate, Notification
from sqlalchemy.orm import joinedload

router = APIRouter()

items_of_interest = [
    "restaurants", "hotels", "tours", "archaeological tourism", "for fun", "museum",
    "water places", "games", "religious tourism", "malls", "parks", "natural views"
]

@router.get("/may_liked_it")
async def get_recommended_items(current_user: str = Depends(get_current_user)):
    try:
        recommended_items = random.sample(items_of_interest, min(3, len(items_of_interest)))
        return {"user_id": current_user, "recommended_items": recommended_items}
    except Exception as e:
        return {"message": str(e)}


user_notifications = {}
@router.get("/notifications")
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

@router.post("/create_plan")
async def create_plan(
        plan_data: PlanCreate,
        current_user: str = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Create a plan for the current user.
    """
    try:
        user = db.query(User).filter(User.user_email == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if the destination exists
        destination = plan_data.destination
        country_exists = db.query(Place).filter(Place.place_loc.ilike(f"%{destination}%")).first()
        if not country_exists:
            raise HTTPException(status_code=404, detail=f"Country '{destination}' not found in the database")

        # Check if all specified places, hotels, and restaurants exist in the destination
        places_not_found = []
        for place_name in plan_data.place_names:
            place = db.query(Place).filter(Place.place_name == place_name,
                                           Place.place_loc.ilike(f"%{destination}%")).first()
            if not place:
                places_not_found.append(place_name)

        hotels_not_found = []
        for hotel_name in plan_data.hotel_names:
            hotel = db.query(Hotel).filter(Hotel.hotel_name == hotel_name,
                                           Hotel.hotel_loc.ilike(f"%{destination}%")).first()
            if not hotel:
                hotels_not_found.append(hotel_name)

        restaurants_not_found = []
        for rest_name in plan_data.restaurant_names:
            restaurant = db.query(Restaurant).filter(Restaurant.rest_name == rest_name,
                                                     Restaurant.rest_loc.ilike(f"%{destination}%")).first()
            if not restaurant:
                restaurants_not_found.append(rest_name)

        if places_not_found or hotels_not_found or restaurants_not_found:
            not_found_message = ""
            if places_not_found:
                not_found_message += f"Places not found: {', '.join(places_not_found)}. "
            if hotels_not_found:
                not_found_message += f"Hotels not found: {', '.join(hotels_not_found)}. "
            if restaurants_not_found:
                not_found_message += f"Restaurants not found: {', '.join(restaurants_not_found)}. "

            return {"message": "Plan not created", "missing_entries": not_found_message}

        # Create Plan instance
        plan = Plan(
            plan_budget=plan_data.plan_budget,
            plan_review=plan_data.plan_review,
            plan_duration=plan_data.plan_duration,
            destination=destination,
            plan_is_recommended=plan_data.plan_is_recommended
        )
        db.add(plan)
        db.flush()

        user_plan = UserPlan(user_id=user.user_id, plan_id=plan.plan_id)
        db.add(user_plan)

        for place_name in plan_data.place_names:
            place = db.query(Place).filter(Place.place_name == place_name,
                                           Place.place_loc.ilike(f"%{destination}%")).first()
            db.execute(plan_place.insert().values(plan_id=plan.plan_id, place_id=place.place_id))

        for hotel_name in plan_data.hotel_names:
            hotel = db.query(Hotel).filter(Hotel.hotel_name == hotel_name,
                                           Hotel.hotel_loc.ilike(f"%{destination}%")).first()
            db.execute(plan_hotel.insert().values(plan_id=plan.plan_id, hotel_id=hotel.hotel_id))

        for rest_name in plan_data.restaurant_names:
            restaurant = db.query(Restaurant).filter(Restaurant.rest_name == rest_name,
                                                     Restaurant.rest_loc.ilike(f"%{destination}%")).first()
            db.execute(plan_restaurant.insert().values(plan_id=plan.plan_id, rest_id=restaurant.rest_id))

        db.commit()

        return {"message": "Plan created successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create plan: {e}")
    finally:
        db.close()

@router.get("/history plans")
async def get_saved_plans(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.user_email == current_user).first()
        if user:
            user_plans = db.query(UserPlan).join(Plan).options(joinedload(UserPlan.plan)).filter(UserPlan.user_id == user.user_id).all()

            saved_plans_response = []
            for user_plan in user_plans:
                saved_plan = PlanCreate(
                    plan_budget=user_plan.plan.plan_budget,
                    plan_review=user_plan.plan.plan_review,
                    plan_duration=user_plan.plan.plan_duration,
                    destination=user_plan.plan.destination,
                    plan_is_recommended=user_plan.plan.plan_is_recommended
                )


                places = db.query(Place.place_name).join(plan_place).filter(plan_place.c.plan_id == user_plan.plan_id).all()
                saved_plan.places = [place[0] for place in places]


                hotels = db.query(Hotel.hotel_name).join(plan_hotel).filter(plan_hotel.c.plan_id == user_plan.plan_id).all()
                saved_plan.hotels = [hotel[0] for hotel in hotels]


                restaurants = db.query(Restaurant.rest_name).join(plan_restaurant).filter(plan_restaurant.c.plan_id == user_plan.plan_id).all()
                saved_plan.restaurants = [restaurant[0] for restaurant in restaurants]

                saved_plans_response.append(saved_plan)

            return {"user_plans": saved_plans_response}
        else:
            return {"message": "User not found."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch user plans: {e}")
    finally:
        db.close()

@router.post("/survey/")
async def survey(survey_response: SurveyResponse, current_user_email: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.user_email == current_user_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

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



@router.get("/out-put survey")
async def get_user_survey(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(ForUser).filter(ForUser.user_email == current_user).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        survey = db.query(Survey).filter(Survey.user_id == user.user_id).order_by(Survey.survey_id.desc()).first()

        if not survey:
            raise HTTPException(status_code=404, detail="Survey not found for the current user")

        options = db.query(Option).filter(Option.survey_id == survey.survey_id).all()

        categories = [option.category for option in options]

        return {"categories": categories}  
    except SQLAlchemyError as e:
        return {"message": f"Database error: {str(e)}"}