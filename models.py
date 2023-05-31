from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base

class Cms_users(Base):
    __tablename__ = "cms_users"

    id = Column(String, primary_key=True)
    
    first_name = Column(String, nullable=False)
    last_name = Column(String)
    email = Column(String, unique=True, nullable=False)
    emp_id = Column(String, unique=True)
    password = Column(String, nullable=False)
    role = Column(String, default="subscriber")
    phone = Column(String, unique=True, nullable=False)
    email_verified = Column(Boolean, default=False)
    phone_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=None, onupdate=func.now())
    is_active = Column(Boolean, default=False)
    otp_table = relationship("Otp_table", back_populates="user")

class Token(Base):
    __tablename__ = "tokens"

    id = Column(String, primary_key=True)
    device_id = Column(String, unique=True)
    access_token = Column(String)
    user_id = Column(String, ForeignKey('cms_users.id'), nullable=False)
    cms_user = relationship(Cms_users)

class Otp_table(Base):
    __tablename__ = "otps"
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('cms_users.id'), nullable=False)
    phone_code = Column(String, nullable=False)
    phone_number = Column(String, nullable=False)
    email = Column(String, nullable=False)
    otp_code = Column(String, nullable=False)
    expiry_date = Column(DateTime)
    no_of_attempts = Column(Integer, nullable=False)
    is_expired = Column(Boolean, nullable=False, default=False)
    user = relationship("Cms_users", back_populates="otp_table")

class User_roles(Base):
    __tablename__ = "user_roles"

    id = Column(String, primary_key=True)
    role_name = Column(String, unique=True, nullable=False)
    permissions = Column(postgresql.ARRAY(String), nullable=False)
    status = Column(Boolean, default=True)

class User_permissions(Base):
    __tablename__ = "user_permissions"

    id = Column(String, primary_key=True)
    permission_name = Column(String, unique=True, nullable=False)
    permission_type = Column(String, nullable=False)
    collection = Column(String, nullable=False)
    status=Column(Boolean, default=False)
