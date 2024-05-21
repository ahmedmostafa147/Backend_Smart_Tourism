from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from data.database import get_db
from helper.models import RecentSearch, User
from helper.schemas import SearchParams
from functions.auth import get_current_user

router = APIRouter()

def query_database(country: str, governorate: str, category: str, name: str):
    
    pass

@router.post("/")
async def search(
    search_params: SearchParams,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.user_email == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        recent_search = RecentSearch(
            user_id=user.user_id,
            country=search_params.country,
            governorate=search_params.governorate,
            category=search_params.category,
            name=search_params.name
        )
        db.add(recent_search)
        db.commit()

        recent_searches = db.query(RecentSearch).filter(RecentSearch.user_id == user.user_id).order_by(RecentSearch.id.desc()).all()

        if len(recent_searches) > 10:
            oldest_searches_to_delete = recent_searches[10:]
            for search_to_delete in oldest_searches_to_delete:
                db.delete(search_to_delete)
            db.commit()

        search_results = query_database(
            search_params.country,
            search_params.governorate,
            search_params.category,
            search_params.name
        )
        return {"results": search_results}
    except SQLAlchemyError as e:
        db.rollback()
        return {"message": f"Database error: {str(e)}"}
    finally:
        db.close()

@router.get("/recent_searches")
async def get_recent_searches(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.user_email == current_user).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        recent_searches = db.query(RecentSearch).filter(RecentSearch.user_id == user.user_id).order_by(RecentSearch.id.desc()).limit(10).all()
        return {"recent_searches": recent_searches}
    except SQLAlchemyError as e:
        return {"message": f"Database error: {str(e)}"}
    finally:
        db.close()
