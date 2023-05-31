from pydantic import BaseModel, EmailStr, constr, validator
from typing import List
from enum import Enum

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]com$'
pass_regex='((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})'

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"

class AllowedRoles(str, Enum):
    VALUE1 = "super_admin"
    VALUE2 = "admin"
    VALUE3 = "editor"
    VALUE4 = "author"
    VALUE5 = "subscriber"

class CmsBase(BaseModel):
    first_name: str
    last_name: str = None
    email: str
    emp_id: str = None
    password: str
    role: str
    phone: str

class CmsUpdate(BaseModel):
    first_name: str
    last_name: str = None
    email: str
    emp_id: str = None
    role: str
    phone: str

class CmsLogin(BaseModel):
    email: str
    password: str

class CmsUpdatePassword(BaseModel):
    password: str

class EmailSchema(BaseModel):
    email: List[EmailStr]

class RoleSchema(BaseModel):
    role_name: str
    permissions: List[str]
    status: bool

class PermissionSchema(BaseModel):
   permission_name: str
   permission_type: str 
   collection: str
   status: bool

class UpdateStatusSchema(BaseModel):
    id: str
    is_active: bool
    role: str