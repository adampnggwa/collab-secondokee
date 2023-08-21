from pydantic import BaseModel
from typing import List
from typing import Optional

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
