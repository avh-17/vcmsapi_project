from pydantic import BaseModel, constr, EmailStr
from typing import List
import datetime

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]com$'
pass_regex='((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})'


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"

class CmsBase(BaseModel):
    first_name: str
    last_name: str = None
    email: constr(regex=regex)
    emp_id: str = None
    password: constr(regex=pass_regex)
    role: str
    phone: str
    otp: int = None

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
