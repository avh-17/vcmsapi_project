import uuid, random
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from sqlalchemy.orm import Session
from schemas import CmsBase, CmsLogin, CmsUpdate, CmsUpdatePassword 
from fastapi_jwt_auth import AuthJWT
from models import Cms_users, Revoked_tokens, Otp_table, Token
from database import SessionLocal
from passlib.context import CryptContext
from funcs import mail
from pydantic import EmailStr
from fastapi_mail import FastMail, MessageSchema

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

# def update_user(user_data: CmsUpdate, user_id: str, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):   
@router.put("/users/{user_id}")
def update_user(user_data: CmsUpdate, user_id: str, token:str, db: Session = Depends(get_db)): 
    revoked_token = db.query(Revoked_tokens).filter_by(token=token).first()
    if revoked_token:
        raise HTTPException(status_code=404, detail="Your token has been revoked, please log in.")
    try:
        user = db.query(Cms_users).filter(Cms_users.id == user_id).first()
        token = db.query(Token).filter(Token.access_token == token).first()

        if user is None or token is None:
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
        token = db.query(Token).filter(Token.user_id == user.id).first()
        print(token)
        if token is None:
            token = Token(
                id = uuid.uuid4().hex,
                access_token = access_token,
                refresh_token = refresh_token,
                user_id = user.id
            )
        token.access_token = access_token,
        token.refresh_token = refresh_token,
        db.add(token)
        db.commit()
        return {"access_token": access_token, "refresh_token": refresh_token}
    raise HTTPException(status_code=404, detail="Invalid credentials.")

@router.post("/logout")
def logout(token: str, db:Session=Depends(get_db)):
    revoked_token = Revoked_tokens(
        id=uuid.uuid4().hex,
        token=token
    )
    db.add(revoked_token)
    db.commit()

    return {"message":"you have logged out."}

@router.put("/forgotpassword")
def forgotpassword(user_otp: str, user_data: CmsUpdatePassword, db:Session=Depends(get_db)):
    otpuser = db.query(Otp_table).filter(Otp_table.otp_code==user_otp).first()
    user = db.query(Cms_users).filter(Cms_users.id==otpuser.user_id).first()
    if user:
        user.password = get_password_hash(user_data.password)

    db.add(user)
    db.commit()
    return {"msg":"user password updated."}

@router.get('/sendotp')
def send_email_otp(email: str, db: Session = Depends(get_db)):
    user = db.query(Cms_users).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = random.randint(100000, 999999)
    otp_user = db.query(Otp_table).filter(Otp_table.user_id==user.id).first()
    
    if otp_user is None:
        otp_user = Otp_table(
            id=uuid.uuid4().hex,
            user_id=user.id,
            phone_code=otp,
            phone_number=user.phone,
            email=user.email,
            otp_code=otp,
            expiry_date = datetime.utcnow()+timedelta(minutes=5),
            no_of_attempts=0
        )
    otp_user.phone_code=otp,
    otp_user.otp_code=otp,
    otp_user.expiry_date = datetime.utcnow()+timedelta(minutes=5),
    otp_user.no_of_attempts+=1
    db.add(otp_user)
    db.commit()

    try:
        message = MessageSchema(
            subject="OTP for reset password",
            recipients=[email],
            body=str(otp),
            subtype="html"  # Optional: specify the subtype as needed
        )
        mail.send_message(message)
    except Exception as e:
        return f'Error sending email: {str(e)}', 500

    return f'OTP sent successfully! {otp}'


    
    






