import uvicorn
from fastapi import FastAPI

from app.routers import auth, resources

app = FastAPI()
app.include_router(auth.router)
app.include_router(resources.router)


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
