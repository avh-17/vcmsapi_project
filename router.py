from fastapi import Depends, FastAPI, HTTPException, APIRouter, Header, requests, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig, MessageType
from sqlalchemy.orm import Session
from schemas import CmsBase, CmsOTP, CmsLogin, CmsUpdate, TokenRevokeRequest
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from models import Cms_users, Revoked_tokens
from database import SessionLocal, engine
import uvicorn, bcrypt, datetime, uuid, random, smtplib
from passlib.context import CryptContext
from funcs import send_email
from typing import List
from pydantic import EmailStr, BaseModel
from email.message import EmailMessage

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

@router.post("/register")
def create_user(user: CmsBase, db: Session = Depends(get_db)):
    db_user = Cms_users(
        id = uuid.uuid4().hex,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        emp_id=user.emp_id,
        password=get_password_hash(user.password),
        role=user.role,
        phone=user.phone
    )
    db.add(db_user)
    db.commit()
    return {
        "response": {
            "code": 201,
            "status": "success",
            "alert": [{
                "message": "created successfully",
                "type": "created",
            }],
            "is_data": 0
        }
    }

@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(Cms_users).all()
 
@router.get("/users/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db)):
    user = db.query(Cms_users).filter(Cms_users.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.put("/users/{user_id}")
def update_user(user_data: CmsUpdate, user_id: str, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):   
    revoked_token = db.query(Revoked_tokens).filter_by(token=token).first()
    print(revoked_token)
    if revoked_token:
        return {"message":"your token has expired"}
    try:
        user = db.query(Cms_users).filter(Cms_users.id == user_id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        user.first_name=user_data.first_name,
        user.last_name=user_data.last_name,
        user.email=user_data.email,
        user.emp_id=user_data.emp_id,
        user.role=user_data.role,
        user.phone=user_data.phone

        db.add(user)
        db.commit()
        return f"User with ID {user_id} has been updated."
    except PyJWTError:
        return {"message": "Invalid token"}
    

@router.delete("/users/{user_id}")
def del_user(user_id: str, db: Session = Depends(get_db)):
    user = db.query(Cms_users).get(user_id)
    print(user)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {f"User with ID {user_id} deleted."}

@router.post("/login")
def login(user_data: CmsLogin, db:Session=Depends(get_db), Authorize: AuthJWT = Depends()):
    user = db.query(Cms_users).filter(Cms_users.email == user_data.email).first()
    passw = user_data.password

    if user and verify_password(passw, user.password):
            access_token = Authorize.create_access_token(subject=user.email)
            refresh_token = Authorize.create_refresh_token(subject=user.email)
            return {"access_token": access_token, "refresh_token": refresh_token}
    return {"msg":"invalid credentials."}

@router.post("/logout")
def logout(user:TokenRevokeRequest, db:Session=Depends(get_db), token: str = Depends(oauth2_scheme)):
    revoked_token = Revoked_tokens(
        id=uuid.uuid4().hex,
        token=user.token
    )
    db.add(revoked_token)
    db.commit()

    return {"Message":"You have logged out."}
    






