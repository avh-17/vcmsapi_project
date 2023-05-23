import uuid, random
from typing import List
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, APIRouter, status
from fastapi.security import OAuth2PasswordRequestForm
from jwt import PyJWTError
from sqlalchemy.orm import Session
from schemas import CmsBase, CmsUpdate, CmsUpdatePassword, RoleSchema, PermissionSchema, UpdateStatusSchema
from models import Cms_users, Otp_table, Token, User_roles, User_permissions
from database import SessionLocal
from funcs import get_db, get_password_hash, verify_password, create_access_token, send_email, oauth2_scheme, ACCESS_TOKEN_EXPIRE_MINUTES
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
    user_role = db.query(User_roles).filter_by(role_name=db_user.role).first()

    if user_role and not user_role.status:
        raise HTTPException(status_code=404, detail="Please set a different user role")
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

@router.put("/verifyuser")
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

@router.post("/roles")
def add_role(role_data: RoleSchema,token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user_role = db.query(User_roles).filter_by(role_name=role_data.role_name).first()
    if user_role:
        raise HTTPException(status_code=400, detail="This role already exists.")
    role = User_roles(
        id = uuid.uuid4().hex,
        role_name = role_data.role_name,
        permissions = role_data.permissions,
        status = role_data.status
    )
    db.add(role)
    db.commit()
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "new user role added."
                }]
            }
    }

@router.get("/getroles")
def get_roles(db: Session = Depends(get_db)):
    return db.query(User_roles).all()

@router.put("/updaterole")
def update_role(role_id: str, role_data:RoleSchema,token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    role=db.query(User_roles).filter_by(id=role_id).first()
    if not role:
        raise HTTPException(status_code=400, detail="This role was not found.")
    role.role_name = role_data.role_name
    role.permissions = role_data.permissions
    role.status = role_data.status

    db.add(role)
    db.commit()
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"role id {role_id} has been updated."
                }]
            }
    } 
    
@router.post("/perm")
def add_permissions(permission_data: PermissionSchema,token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user_permissions = db.query(User_permissions).filter_by(permission_name=permission_data.permission_name).first()
    if user_permissions:
        raise HTTPException(status_code=400, detail="This user permission already exists.")

    user_permissions = User_permissions(
        id=uuid.uuid4().hex,
        permission_name = permission_data.permission_name,
        permission_type = permission_data.permission_type,
        collection = permission_data.collection,
        status = permission_data.status
    )
    db.add(user_permissions)
    db.commit()
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "new user permissions added."
                }]
            }
    }

@router.get("/getperm")
def get_permissions(db: Session = Depends(get_db)):
    return db.query(User_permissions).all()

router.put("/updateperm")
def update_permissions(perm_id: str, perm_data: PermissionSchema, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user_perm = db.query(User_permissions).filter_by(id=perm_id).first()

    if not user_perm:
        raise HTTPException(status_code=400, detail="This user permission was not found.")
    
    user_perm.permission_name = perm_data.permission_name
    user_perm.permission_type = perm_data.permission_type
    user_perm.collection = perm_data.collection

    db.add(user_perm)
    db.commit()

    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"user permissions id {perm_id} updated."
                }]
            }
    }

@router.put("/updatestatus")
def update_status(users_data: List[UpdateStatusSchema], bulk: bool, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    if bulk:
        for user_data in users_data:
            user = db.query(Cms_users).filter_by(id=user_data.id).first()
            if not user:
                raise HTTPException(status_code=400, detail="user not found.")
             
            user.is_active = user_data.is_active
            user.role = user_data.role

            db.add(user)
            db.commit()

        return{
                "response": {
                    "code": 200,
                    "status": "success",
                    "alert": [{
                        "message": f"multiple user ids updated."
                    }]
                }
        }
        
    user = db.query(Cms_users).filter_by(id=users_data[0].id).first()
    if not user:
        raise HTTPException(status_code=400, detail="user not found.")
    
    user.is_active = users_data[0].is_active
    user.role = users_data[0].role

    db.add(user)
    db.commit()
    return{
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"user id {user.id} updated."
                }]
            }
    }
   
            



