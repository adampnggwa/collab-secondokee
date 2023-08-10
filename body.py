from pydantic import BaseModel
from typing import List
     
class ProductCreate(BaseModel):
    id: int
    name: str
    description: str
    price: float
    type: str
    size: str

class MetaData(BaseModel):
    code: int
    message: str

class ProductResponse(BaseModel):
    meta: MetaData
    response: List[ProductCreate]

class ProductCreateRequest(BaseModel):
    name: str
    description: str
    price: float
    type: str
    size: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    create_username: str
    create_password: str
