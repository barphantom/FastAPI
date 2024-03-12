from .auth import get_current_user, verify_password, get_password_hash
from starlette.responses import RedirectResponse
from fastapi import Depends, status, APIRouter, Request, Form
from pydantic import BaseModel
from ..models import Base, Users
from sqlalchemy.orm import Session
from ..database import SessionLocal, engine

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


router = APIRouter(
    prefix='/users',
    tags=["users"],
    responses={404: {"description": "Not Found"}}
)

Base.metadata.create_all(bind=engine)
# templates = Jinja2Templates(directory="C:\Bartek\Projekty FastAPI\FullStackApp\TodoApp\\templates")
# templates = Jinja2Templates(directory="TodoApp\\templates")
templates = Jinja2Templates(directory="templates")


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


class UserVerification(BaseModel):
    username: str
    current_password: str
    new_password: str
    confirm_new_password: str


@router.get("/change-password", response_class=HTMLResponse)
async def edit_user_view(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("change-password.html", {"request": request, "user": user})


@router.post("/change-password", response_class=HTMLResponse)
async def change_to_new_password(request: Request, username: str = Form(...), current_password: str = Form(...),
                                 new_password: str = Form(...), confirm_new_password: str = Form(...),
                                 db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    msg = "Invalid username or password."

    user_data: Users = db.query(Users).filter(Users.username == username).first()
    if user_data is not None:
        if username == user_data.username and verify_password(current_password, user_data.hashed_password) and verify_password(
                new_password, get_password_hash(confirm_new_password)):
            user_data.hashed_password = get_password_hash(new_password)
            db.add(user_data)
            db.commit()
            msg = "Password successfully updated!"
            # return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("change-password.html", {"request": request, "user": user, "msg": msg})
