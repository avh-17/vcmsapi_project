from pydantic import BaseModel, constr
import datetime

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]com$'
pass_regex='((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})'

class CmsBase(BaseModel):
    first_name: str
    last_name: str
    email: constr(regex=regex)
    emp_id: str
    password: constr(regex=pass_regex)
    phone: str
    created_at: datetime
    updated_at: datetime

