import smtplib, uuid, random
from email.message import EmailMessage
from fastapi import FastAPI
from datetime import datetime, timedelta
from jose import jwt
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from typing import List
from database import SessionLocal
from email.message import EmailMessage
from schemas import *
from models import *

app = FastAPI()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def add_user(user: CmsBase, db: Session):
    valid_roles = ["super_admin", "admin", "editor", "author", "subscriber"]
    lower_case_role = user.role.lower()
    if lower_case_role not in valid_roles:
        message = """Invalid role. Your role can be "super_admin", "admin", "editor", "author", "subscriber" """
        code = 400
        return {"success": False, "code": code, "message": message}
    
    fld_unique = check_unique(user.phone, user.email, user.emp_id, db)
    if not fld_unique:
        message = "email | phone no | emp_id already exists."
        code = 409
        return {"success": False, "code": code, "message": message}

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
    user_role = db.query(User_roles).filter_by(role_name=db_user.role).first()
    if user.role=="super_admin" and not user_role.status:
        message = "Super admin already exists."
        code = 409
        return {"success": False, "code": code, "message": message}
    if fld_unique:
        if user.role =="super_admin":
            user_role.status=False
            db.add(user_role)
            db.commit()
        db.add(db_user)
        db.commit()
        return {"success": True}
    else:
        return {"success": False}
    
def delete_user(user_id: str, db: Session):
    user = db.query(Cms_users).get(user_id)
    if user is None:
        return False
    user_role = db.query(User_roles).filter_by(role_name=user.role).first()
    if "delete_user" not in user_role.permissions:
        message = "User role permission denied."
        code = 400
        return {"success": False, "code": code, "message": message}
    db.delete(user)
    db.commit()
    return True

def send_otp(email: str, db: Session):
    user = db.query(Cms_users).filter_by(email=email).first()
    if not user:
        return {
            "response": {
                "code": 404,
                "status": "failure",
                "alert": [{
                    "message": "User not found",
                    "type": "failure"
                }],
            }
        }

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
            'success': True,
            'otp': otp
        }

def verify_user(user_otp: str, db: Session):
    otpuser = db.query(Otp_table).filter(Otp_table.otp_code==user_otp).first()
    if otpuser is None:
        message = "Invalid OTP code."
        code = 400
        return {"success": False, "code": code, "message": message}
    user = db.query(Cms_users).filter(Cms_users.id==otpuser.user_id).first()
    user_role = db.query(User_roles).filter_by(role_name=user.role).first()
    
    # if "verify_user" not in user_role.permissions:
    #     message = "User role permission denied."
    #     code = 400
    #     return {"success": False, "code": code, "message": message}
    if datetime.utcnow() >= otpuser.expiry_date:
        otpuser.is_expired=True
        db.add(otpuser)
        db.commit()
        message = "Your OTP has expired."
        code = 400
        return {"success": False, "code": code, "message": message}
    
    if user:
        user.email_verified=True
        user.phone_verified=True
        db.add(user)
        db.commit()
        return {"success": True}
    
    return {"success": False, "code": 400, "message": "User not found."}

def forgot_pass(user_otp: str, user_data: CmsUpdatePassword, db:Session):
    otpuser = db.query(Otp_table).filter(Otp_table.otp_code==user_otp).first()
    user = db.query(Cms_users).filter(Cms_users.id==otpuser.user_id).first()
    user_role = db.query(User_roles).filter_by(role_name=user.role).first()
    if "update_user" not in user_role.permissions:
        message = "User role permission denied."
        code = 400
        return {"success": False, "code": code, "message": message}
    if datetime.utcnow() >= otpuser.expiry_date:
        otpuser.is_expired=True
        db.add(otpuser)
        db.commit()
        message = "Your OTP has expired."
        code = 400
        return {"success": False, "code": code, "message": message}
    
    if user:
        user.password = get_password_hash(user_data.password)
        db.add(user)
        db.commit()
        return {"success": True}

    return {"success": False, "code": 400, "message": "User not found."}

def role_add(role_data: RoleSchema, db: Session):
    user_role = db.query(User_roles).filter_by(role_name=role_data.role_name).first()
    if user_role:
        return False
    if "add_role" not in user_role.permissions:
        message = "User role permission denied."
        code = 400
        return {"success": False, "code": code, "message": message}
    role = User_roles(
        id = uuid.uuid4().hex,
        role_name = role_data.role_name,
        permissions = role_data.permissions,
        status = role_data.status
    )
    db.add(role)
    db.commit()
    return True

def role_update(role_id: str, role_data: RoleSchema, db: Session):
    role=db.query(User_roles).filter_by(id=role_id).first()
    if "update_role" not in role.permissions:
        message = "User role permission denied."
        code = 400
        return {"success": False, "code": code, "message": message}
    if not role:
        return None
    role.role_name = role_data.role_name
    role.permissions = role_data.permissions
    role.status = role_data.status

    db.add(role)
    db.commit()
    return role

def permissions_update(perm_id, perm_data, db):
    user_perm = db.query(User_permissions).filter_by(id=perm_id).first()
    if user_perm:
        user_perm.permission_name = perm_data.permission_name
        user_perm.permission_type = perm_data.permission_type
        user_perm.collection = perm_data.collection

        db.add(user_perm)
        db.commit()
        return user_perm
    else:
        False

def permission_delete(perm_id:str, db:Session):
    perm = db.query(User_permissions).get(perm_id)
    if perm:
        db.delete(perm)
        db.commit()
        return True
    else:
        False

def update_multiple_users(users_data: List[UpdateStatusSchema], db: Session):
    for user_data in users_data:
            user = db.query(Cms_users).filter_by(id=user_data.id).first()
            if not user:
                message = "User not found"
                code = 404
                return {"success": False, "code": code, "message": message}
            user_role = db.query(User_roles).filter_by(role_name=user.role).first()
            if "update_user" not in user_role.permissions:
                message = "User role permission denied."
                code = 400
                return {"success": False, "code": code, "message": message}
                    
            user.is_active = user_data.is_active
            user.role = user_data.role

            db.add(user)
            db.commit()         

    return True

def update_single_user(user_id: str, user_data: CmsUpdate, db: Session):
    user = db.query(Cms_users).filter(Cms_users.id == user_id).first()
    user_otp = db.query(Otp_table).filter(user.id == Otp_table.user_id).first()
    if user is None:
        message = "User not found"
        code = 404
        return {"success": False, "code": code, "message": message}
    
    user_role = db.query(User_roles).filter_by(role_name=user.role).first()
    if "update_user" not in user_role.permissions:
        message = "User role permission denied."
        code = 400
        return {"success": False, "code": code, "message": message}
    
    if user_otp:
        db.delete(user_otp)
        db.commit
    user.first_name=user_data.first_name,
    user.last_name=user_data.last_name,
    user.email=user_data.email,
    user.emp_id=user_data.emp_id,
    if user.role and not user_role.status:
        message = "Super admin user role already taken."
        code = 404
        return {"success": False, "code": code, "message": message}
    user.role=user_data.role,
    user.phone=user_data.phone,
    if user_role.role_name=="super_admin":
        user_role.status=False
        db.add(user_role)
        db.commit()
    db.add(user)
    db.commit()
    return user

def role_delete(role_id:str, db:Session):
    role = db.query(User_roles).get(role_id)
    if role:
        db.delete(role)
        db.commit()
        return True
    else:
        False

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

app = FastAPI()

def send_email(subject: str,body: str,sender_email: str,recipient_email: str):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg.set_content(body)

    try:
        with smtplib.SMTP("smtp.office365.com", 587) as server:
            server.starttls()
            server.login("nicemltstng@outlook.com", "Valtech123")
            server.send_message(msg)
    except Exception as e:
        return {"message": "Failed to send email", "error": str(e)}
    
    return {"message": "Email sent successfully"}

def check_unique(phoneno, emailid, empid, db):
    phone = db.query(Cms_users).filter(Cms_users.phone == phoneno).first()
    email = db.query(Cms_users).filter(Cms_users.email == emailid).first()
    emp_id = db.query(Cms_users).filter(Cms_users.emp_id == empid).first()
    if phone or email or emp_id:
        return False
    return True
