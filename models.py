from sqlalchemy import Column, Integer, String, Boolean
from database import Base, engine

class UserModel(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    phno = Column(String, unique=True)
    email_verified = Column(Boolean, default=False)
    
# Cms_users
# 5.	ID (primary key)
# 6.	First_name (mandatory)
# 7.	Last_name (optional)
# 8.	Email (mandatory)
# 9.	Emp_id (optional)
# 10.	Password (mandatory)
# 11.	Role (mandatory)
# 12.	Phone (mandatory)
# 13.	Email_verified (mandatory)
# 14.	Phone_verified (mandatory)
# 15.	createdAt (mandatory)
# 16.	updatedAt (optional)
# 17.	is_active (mandatory)




