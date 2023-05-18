from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base, engine

class Cms_users(Base):
    __tablename__ = "cms_users"

    id = Column(String, primary_key=True)
    
    first_name = Column(String, unique=True, nullable=False)
    last_name = Column(String, unique=True)
    email = Column(String, unique=True, nullable=False)
    emp_id = Column(String, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    email_verified = Column(Boolean, default=False)
    phone_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=None, onupdate=func.now())
    is_active = Column(Boolean, default=False)

class Token(Base):
    __tablename__ = "tokens"

    id = Column(String, primary_key=True)
    device_id = Column(String, unique=True)
    access_token = Column(String)
    refresh_token = Column(String)
    user_id = Column(String, ForeignKey('cms_users.id'), nullable=False)
    expiry_time = Column(DateTime)
    is_expired = Column(Boolean, nullable=False, default=False)
    cms_user = relationship(Cms_users)

class Otp_table(Base):
    __tablename__ = "otps"
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('cms_users.id'), nullable=False)
    phone_code = Column(String, nullable=False)
    phone_number = Column(String, ForeignKey('cms_users.phone'), nullable=False)
    email = Column(String, ForeignKey('cms_users.email'), nullable=False)
    otp_code = Column(String, nullable=False)
    expiry_date = Column(DateTime)
    no_of_attempts = Column(Integer, nullable=False)
    is_expired = Column(Boolean, nullable=False, default=False)

class Revoked_tokens(Base):
    __tablename__ = "revoked_tokens"
    id = Column(String, primary_key=True)
    token = Column(String, nullable=False)


