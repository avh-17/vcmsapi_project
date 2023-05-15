from fastapi import Depends, FastAPI, HTTPException, APIRouter, Header
from sqlalchemy.orm import Session
from schemas import UserBase
from models import UserModel
from database import SessionLocal, engine
import uvicorn, bcrypt

router = APIRouter()

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

@router.post("/users")
def create_user(user: UserBase, db: Session = Depends(get_db)):
    # if:
    db_user = UserModel(username=user.username, email=user.email, password=bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), phno=user.phno)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(UserModel).all()
 
@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.delete("/users/{user_id}")
def del_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserModel).get(user_id)
    print(user)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {f"User with ID {user_id} deleted."}