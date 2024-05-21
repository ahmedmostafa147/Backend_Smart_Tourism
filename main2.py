from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from functions.auth import router as auth_router
from functions.search import router as search_router
app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="8c87d814d4be0ddc08364247da359a61941957e84f62f3cd0e87eb5d853a4144")

app.include_router(auth_router, prefix="functions/auth.py", tags=["auth"])
app.include_router(search_router, prefix="functions/search", tags=["search"])

     