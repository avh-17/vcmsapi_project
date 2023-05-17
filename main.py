from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from schemas import Settings
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from database import engine, Base
from router import router as my_router
import uvicorn

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