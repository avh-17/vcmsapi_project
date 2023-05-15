from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
from schemas import UserBase
import models
from database import SessionLocal, engine, Base
from router import router as my_router
import uvicorn

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(my_router)

if __name__ =='__main__':
    uvicorn.run(app, host="0.0.0.0")