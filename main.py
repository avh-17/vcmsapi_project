from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from schemas import CmsBase, Settings
import models
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from database import SessionLocal, engine, Base
from router import router as my_router
import uvicorn
from pydantic import BaseModel

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(my_router)

@AuthJWT.load_config
def get_config():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

if __name__ =='__main__':
    uvicorn.run(app, host="0.0.0.0")