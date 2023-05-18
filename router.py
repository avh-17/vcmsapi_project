import uuid, random
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, APIRouter, status
from fastapi.security import OAuth2PasswordRequestForm
from jwt import PyJWTError
from sqlalchemy.orm import Session
from schemas import CmsBase, CmsUpdate, CmsUpdatePassword
from models import Cms_users, Otp_table, Token
from database import SessionLocal
from funcs import get_db, get_password_hash, oauth2_scheme, verify_password, ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, send_email
from typing import Annotated

router = APIRouter()

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
            }]
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
def update_user(user_data: CmsUpdate, user_id: str, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)): 
    try:
        user = db.query(Cms_users).filter(Cms_users.id == user_id).first()

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
        return {
            "response": {
                "code": 201,
                "status": "success",
                "alert": [{
                    "message": f"user with ID {user_id} updated successfully",
                    "type": "updated",
                }]
            }
        }

    except PyJWTError:
        return {"message": "Invalid token"}
    

@router.delete("/users/{user_id}")
def del_user(user_id: str, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user = db.query(Cms_users).get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"user with ID {user_id} deleted.",
                    "type": "delete",
                }]
            }
        }

@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db:Session=Depends(get_db)
):
    user = db.query(Cms_users).filter(Cms_users.email==form_data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(form_data.password, user.password):
        return False
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    token = Token(
        id=uuid.uuid4().hex,
        access_token=access_token,
        user_id=user.id
    )
    db.add(token)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}

@router.put("/forgotpassword")
def forgotpassword(user_otp: str, user_data: CmsUpdatePassword, db:Session=Depends(get_db)):
    otpuser = db.query(Otp_table).filter(Otp_table.otp_code==user_otp).first()
    print(otpuser)
    user = db.query(Cms_users).filter(Cms_users.id==otpuser.user_id).first()
    if datetime.utcnow() >= otpuser.expiry_date:
        otpuser.is_expired=True
        db.add(otpuser)
        db.commit()
        raise HTTPException(status_code=400, detail="your otp has expired.") 
    
    if user:
        user.password = get_password_hash(user_data.password)

    db.add(user)
    db.commit()
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "password updated.",
                    "type": "update",
                }]
            }
        }

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
    otp_user.is_expired = False
    db.add(otp_user)
    db.commit()

    send_email("Email verification OTP",str(otp),"nicemltstng@outlook.com", user.email)
   
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"otp {otp} sent."
                }]
            }
        }

@router.put("/verifyuser/")
def verifyuser(user_otp: str, db: Session = Depends(get_db)):
    otpuser = db.query(Otp_table).filter(Otp_table.otp_code==user_otp).first()
    user = db.query(Cms_users).filter(Cms_users.id==otpuser.user_id).first()
    if datetime.utcnow() >= otpuser.expiry_date:
        otpuser.is_expired=True
        db.add(otpuser)
        db.commit()
        raise HTTPException(status_code=400, detail="your otp has expired.") 
    
    if user:
        user.email_verified=True
        user.phone_verified=True

    db.add(user)
    db.commit()
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "email and phone verified."
                }]
            }
        }


    
    






