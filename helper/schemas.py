from pydantic import BaseModel, EmailStr,validator
from typing import Optional
from pydantic import Field
from typing import List, Optional
from pydantic import BaseModel

class UserRegistration(BaseModel):
    first_name: str = Field(..., min_length=3, max_length=8)
    last_name: str = Field(..., min_length=3, max_length=8)
    user_password: str
    user_email: EmailStr
    user_location: Optional[str] = None

    @validator("user_email")
    def validate_email(cls, v):
        allowed_domains = ["yahoo.com", "gmail.com", "mail.com", "outlook.com", "hotmail.com"]
        email_domain = v.split('@')[1]
        if email_domain not in allowed_domains:
            raise ValueError("Only Yahoo, Gmail, Mail, Outlook, and Hotmail domains are allowed")
        return v

class UserLogin(BaseModel):
    user_email: EmailStr
    user_password: str

class UserUpdate(BaseModel):
    first_name: str
    last_name: str
    user_location: str

class SearchParams(BaseModel):
    country: Optional[str] = "string"
    governorate: Optional[str] = "string"
    category: Optional[str] = "string"
    name: Optional[str] = "string"

class Notification(BaseModel):
    user_email: str
    message: str

class SurveyResponse(BaseModel):
    category: str

class PlanCreate(BaseModel):
    plan_budget: int
    plan_review: Optional[str] = None
    plan_duration: int
    destination: str
    plan_is_recommended: bool
    restaurant_names: List[str] = []
    hotel_names: List[str] = []
    place_names: List[str] = []

class FavoriteCreate(BaseModel):
    type: str
    name: str
    location: str
