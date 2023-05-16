from sqlalchemy import Column, Integer, String, Boolean, DateTime
from database import Base, engine

class Cms_users(Base):
    __tablename__ = "cms_users"

    id = Column(Integer, primary_key=True)
    first_name = Column(String, unique=True, nullable=False)
    last_name = Column(String, unique=True)
    email = Column(String, unique=True, nullable=False)
    emp_id = Column(String, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    email_verified = Column(Boolean, default=False)
    phone_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime)
    is_active = Column(Boolean, default=False)
    




