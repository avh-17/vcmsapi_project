from pydantic import BaseModel, constr

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]com$'
pass_regex='((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{8,64})'

class UserBase(BaseModel):
    username: str
    email: constr(regex=regex)
    phno: str
    password: constr(regex=pass_regex)
