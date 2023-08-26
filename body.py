from pydantic import BaseModel
from typing import List

class ProductCreate(BaseModel):
    id: int
    name: str
    brand: str
    description: str
    price: float
    type: str
    size: str
    stock: int 

class MetaData(BaseModel):
    code: int
    message: str

class ProductResponse(BaseModel):
    meta: MetaData
    response: List[ProductCreate]

class ProductCreateRequest(BaseModel):
    name: str
    brand: str 
    description: str
    price: float
    type: str
    size: str
    stock: int 

class UserSignup(BaseModel):
    email: str
    create_password: str

class UserSignin(BaseModel):
    email: str
    password: str
