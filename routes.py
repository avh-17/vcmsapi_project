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
from domain import *
from typing import Annotated

router = APIRouter()

@router.post("/register")
def create_user(user: CmsBase, db: Session = Depends(get_db)):
    result = add_user(user, db)
    if result['success']:
        return {
            "response": {
                "code": 201,
                "status": "success",
                "alert": [{
                    "message": "User created successfully",
                    "type": "created",
                }]
            }
        }
    else:
        return {
            "response": {
                "code": result["code"],
                "status": "failure",
                "alert": [{
                    "message": result["message"],
                    "type": "failure",
                }],
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

@router.get('/sendotp')
def send_email_otp(email: str, db: Session = Depends(get_db)):
   result = send_otp(email, db)
   is_data = 1 if result['success'] else 0

   if result['success']:
        return {
            "response": {
                "code": 201,
                "status": "success",
                "alert": [{
                    "message": "Otp sent successfully",
                    "type": "generated"
                }],
                "otp": result['otp'],
                "is_data": is_data
            }
        }
   else:
        return {
            "response": {
                "code": result["code"],
                "status": "failure",
                "alert": [{
                    "message": result["message"],
                    "type": "failure",
                }],
                "is_data": is_data
            }
        }
   
@router.put("/forgotpassword")
def forgotpassword(user_otp: str, user_data: CmsUpdatePassword, db:Session=Depends(get_db)):
    result = forgot_pass(user_otp, user_data, db)
    if result["success"]:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "Password updated.",
                    "type": "update",
                }]
            }
        }
    else:
        return {
            "response": {
                "code": result["code"],
                "status": "Failure",
                "alert": [{
                    "message": result["message"],
                    "type": "Failure"
                }]
            }
        }


@router.get("/users")
def get_users(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    users =  db.query(Cms_users).all()
    is_data = 1 if users else 0
    if users:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "User fetched successfully ",
                    "type": "Fetch"
                }],
                "data":users,
                "is_data":is_data                
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "failure",
                "alert": [{
                    "message": "User not found",
                    "type": "failure"
                }],
                "is_data":is_data 
            }
        }
 
@router.get("/users/{user_id}")
def get_user(user_id: str, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    user = db.query(Cms_users).filter(Cms_users.id == user_id).first()
    is_data = 1 if user else 0
    if user is None:
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
    user_data = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "emp_id": user.emp_id,
            "role": user.role,
            "phone": user.phone,
            "email_verified": user.email_verified,
            "phone_verified": user.phone_verified,
            "is_active": user.is_active
        }
    return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "User fetched successfully ",
                    "type": "Fetch"
                }],
                "data":user_data,    
                "is_data":is_data         
            }
        }
    

@router.delete("/users/{user_id}")
def del_user(user_id: str, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = delete_user(user_id, db)
    if result:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"user with ID {user_id} deleted successfully.",
                    "type": "delete",
                }]
            }
        }
    else:
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
   
@router.put("/updateuser")
def update_user(bulk: bool, token: Annotated[str, Depends(oauth2_scheme)], users_data: List[UpdateStatusSchema]=None, user_data: CmsUpdate=None, user_id: str=None, db: Session = Depends(get_db)):
    if bulk:
        result = update_multiple_users(users_data, db)
        is_data = 1 if result else 0
        if result:
            return {
                "response": {
                    "code": 200,
                    "status": "success",
                    "alert": [{
                        "message": f"user ids {(user_data.id for user_data in users_data)} updated",
                        "type": "Update",
                    }],
                    "data":users_data,
                    "is_data":is_data
                }
            }
        else:
            return {
                "response": {
                    "code": 404,
                    "status": "Failure",
                    "alert": [{
                        "message": "User ids not updated.",
                        "type": "Failure"
                    }],
                    "is_data":is_data
                }
            }
        
    result = update_single_user(user_id, user_data, db)
    is_data = 1 if result else 0
    if result:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"user id {result.id} updated",
                    "type": "Update",
                }],
                "data":result,
                "is_data":is_data
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "Failure",
                "alert": [{
                    "message": f"User id {user_id} not updated.",
                    "type": "Failure"
                }],
                "is_data":is_data
            }
        }


@router.put("/verifyuser")
def verifyuser(user_otp: str, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = verify_user(user_otp, db)
    if result["success"]:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "User successfully verified.",
                    "type": "Verify"
                }]
            }
        }
    else:
        return {
            "response": {
                "code": result["code"],
                "status": "failure",
                "alert": [{
                    "message": result["message"],
                    "type": "failure"
                }]
            }
        }

@router.post("/roles")
def add_role(role_data: RoleSchema, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = role_add(role_data,db)
    if result:
        return {
            "response": {
                "code": 201,
                "status": "success",
                "alert": [{
                    "message": "New role added successfully",
                    "type": "created",
                }]
            }
        }
    else:
        return {
            "response": {
                "code": 401 | 500,
                "status": "failure",
                "alert": [{
                    "message": "Role already exists | internal server error",
                    "type": "failure",
                }],
            }
        }

@router.get("/getroles")
def get_roles(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = db.query(User_roles).all()
    is_data = 1 if result else 0
    if result:
        return {
            "response": {
                "code": 200,
                "status": "success",
               "alert": [{
                    "message": "Roles fetched successfully ",
                    "type": "Fetch"                    
                }],
                "users": result,
                "is_data":is_data
                
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "failure",
                "alert": [{
                    "message": "No roles found",
                    "type": "failure"
                }],
                "is_data":is_data
            }
        }

@router.put("/updaterole")
def update_role(role_id: str, role_data:RoleSchema, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = role_update(role_id, role_data, db)
    is_data = 1 if result else 0
    if result:
        roles_data = {
                    "role_name": result.role_name,
                    "permissions": result.permissions,
                    "status": result.status
                }
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"Role with role id {role_id} updated successfully",
                    "type": "Update",
                }],
                "data": roles_data,
                "is_data":is_data
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "Failure",
                "alert": [{
                    "message": "Role id not found, Or the Role already exists",
                    "type": "Failure"
                }],
                "is_data":is_data
            }
        }
    
@router.delete("/roles")
def delete_role(role_id: str,token: Annotated[str, Depends(oauth2_scheme)],db: Session = Depends(get_db)):

    result = role_delete(role_id, db)
    if result:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "Role deleted successfully",
                    "type": "deleted"
                }],
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "failure",
                "alert": [{
                    "message": "Role not found",
                    "type": "failure"
                }],
            }
        }
    
@router.post("/perm")
def add_permissions(permission_data: PermissionSchema, token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
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
def get_permissions(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = db.query(User_permissions).all()
    is_data = 1 if result else 0

    if result:
        permission_list = []
        for permission in result:
            permission_data = {
                "id":permission.id,
                "permission_name": permission.permission_name,
                "permission_type": permission.permission_type,
                "collection":permission.collection,
                "status": permission.status
            }
            permission_list.append(permission_data)

        return {
            "response": {
                "code": 200,
                "status": "success",
               "alert": [{
                    "message": "Permission fetched successfully ",
                    "type": "success"
                }],
                "data": permission_list,
                "is_data":is_data
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "failure",
                "alert": [{
                    "message": "No Permissions found",
                    "type": "failure"
                }],
                "is_data":is_data
            }
        }
    
@router.put("/permission")
def update_permissions(perm_id: str, perm_data: PermissionSchema,token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    result = permissions_update(perm_id, perm_data, db)
    is_data = 1 if result else 0

    if result:
        permission = {
                "permission_name": result.permission_name,
                "permission_type": result.permission_type,
                "collection":result.collection,
                "status": result.status
        }
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": f"Failure with permission id {perm_id} updated successfully",
                    "type": "Update",
                }],
                "data":permission,
                "is_data":is_data
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "Failure",
                "alert": [{
                    "message": "Permission id not found",
                    "type": "Failure"
                }],
                "is_data":is_data
            }
        }
    
@router.delete("/permission")
def delete_permission(perm_id: str,token: Annotated[str, Depends(oauth2_scheme)],db: Session = Depends(get_db)):

    result = permission_delete(perm_id, db)
    if result:
        return {
            "response": {
                "code": 200,
                "status": "success",
                "alert": [{
                    "message": "Permission deleted successfully",
                    "type": "deleted"
                }],
            }
        }
    else:
        return {
            "response": {
                "code": 404,
                "status": "failure",
                "alert": [{
                    "message": "Permission not found",
                    "type": "failure"
                }],
            }
        }



   
            



