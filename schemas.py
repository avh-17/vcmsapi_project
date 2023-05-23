from pydantic import BaseModel, constr, EmailStr, validator
from fastapi import HTTPException
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
    email: constr(regex=regex)
    emp_id: str = None
    password: constr(regex=pass_regex)
    role: constr(
        strip_whitespace=True,
        to_lower=True,
        regex=f"({'|'.join(v.value for v in AllowedRoles)})",
    ) = None
    phone: str

    @validator('role')
    def validate_role(cls, value):
        if value not in [v.value for v in AllowedRoles]:
            raise ValueError(f"Invalid value. Allowed values are {', '.join(v.value for v in AllowedRoles)}.")
        return value

class CmsUpdate(BaseModel):
    first_name: str
    last_name: str = None
    email: constr(regex=regex)
    emp_id: str = None
    role: str
    phone: str

class CmsLogin(BaseModel):
    email: constr(regex=regex)
    password: constr(regex=pass_regex)

class CmsUpdatePassword(BaseModel):
    password: constr(regex=pass_regex)

class EmailSchema(BaseModel):
    email: List[EmailStr]

class RoleSchema(BaseModel):
    role_name: constr(
        strip_whitespace=True,
        to_lower=True,
        regex=f"({'|'.join(v.value for v in AllowedRoles)})",
    )
    permissions: List[str]
    status: bool

    @validator('role_name')
    def validate_role(cls, value):
        if value not in [v.value for v in AllowedRoles]:
            raise ValueError(f"Invalid value. Allowed values are {', '.join(v.value for v in AllowedRoles)}.")
        return value

class PermissionSchema(BaseModel):
   permission_name: str
   permission_type: str 
   collection: List[str]
   status: bool

class UpdateStatusSchema(BaseModel):
    id: str
    is_active: bool
    role: str