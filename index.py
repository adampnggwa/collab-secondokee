from fastapi import FastAPI, Body, UploadFile, File, Request, HTTPException
from body import ProductCreate, ProductResponse, MetaData, ProductCreateRequest, UserCreate, UserLogin, MetaDataWithEmail
from fastapi.responses import JSONResponse, RedirectResponse
from reaspon import success_response, error_response
from tortoise.exceptions import IntegrityError
from cryptography.fernet import Fernet
from model import Product, User
from config import init_db
from google_oauth import (
    google_authorization,
    google_auth_callback,
    google_oauth_cb,
)
import requests
import os
import hashlib
import secrets

app = FastAPI()

scopes=['email', 'profile']

# Inisialisasi kunci enkripsi
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

def validate_google_token(token: str) -> dict:
    response = requests.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}")
    return response.json()

def save_uploaded_photo(photo_name: str, uploaded_file: UploadFile):
    photo_dir = "C:\\adampkl\\test upload foto"
    if not os.path.exists(photo_dir):
        os.makedirs(photo_dir)
    file_extension = uploaded_file.filename.split(".")[-1]
    photo_path = os.path.join(photo_dir, f"{photo_name}.{file_extension}")
    with open(photo_path, "wb") as photo_file:
        photo_file.write(uploaded_file.file.read())

def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()

async def perform_signup(user_data: UserCreate) -> dict:
    try:
        user_exists = await User.exists(email=user_data.email)
        if user_exists:
            return error_response(400, "Email already exists")
        salt = secrets.token_hex(16)
        hashed_password = hash_password(user_data.create_password, salt)
        user = await User.create(email=user_data.email, password=hashed_password, salt=salt)
        return success_response(201, "User created successfully")
    except IntegrityError as e:
        return error_response(400, "Error creating user: Email already exists")
    except Exception as e:
        return error_response(500, "Error creating user: Internal Server Error")

async def perform_login(user_data: UserLogin) -> dict:
    try:
        user = await User.get(email=user_data.email)
    except User.DoesNotExist:
        return error_response(404, "User not found")
    if user.password != user_data.password:
        return error_response(400, "Invalid email or password")
    google_token = user_data.google_token
    google_token_info = validate_google_token(google_token)
    if google_token_info.get("error"):
        return error_response(400, "Google token validation failed")

    # Enkripsi token sebelum menyimpannya di basis data
    encrypted_token = cipher_suite.encrypt(google_token.encode("utf-8"))
    user.access_token = encrypted_token
    await user.save()
    return success_response(200, "Login successful")

async def get_all_product() -> ProductResponse:
    all_product = await Product.all()
    response_data = [ProductCreate(id=product.id, name=product.name, description=product.description, price=product.price, type=product.type, size=product.size) for product in all_product]
    return ProductResponse(meta=MetaData(code=200, message="successfully displayed all products"), response=response_data)
    
async def create_product(name: str, description: str, price: float, type: str, size: str) -> ProductResponse:
    product = await Product.create(name=name, description=description, price=price, type=type, size=size)
    data_response = ProductCreate(id=product.id, name=product.name, description=product.description, price=product.price, type=product.type, size=product.size)
    return ProductResponse(meta=MetaData(code=201, message="successfully added product"), response=[data_response])

async def upload_product_photo(name_or_id: str, product_photo: UploadFile = File(...)) -> ProductResponse:
    by_id = name_or_id.isdigit()
    if by_id:
        product = await Product.get_or_none(id=int(name_or_id))
    else:
        product = await Product.get_or_none(name=name_or_id)
    if product is None:
        return ProductResponse(meta=MetaData(code=404, message="Product not found"), response=[])
    photo_name = f"{product.name}_{product.id}"
    save_uploaded_photo(photo_name, product_photo)    
    return ProductResponse(meta=MetaData(code=200, message="Product photo uploaded successfully"), response=[])

async def update_product(name_or_id: str, new_name: str = None, new_description: str = None, new_price: float = None, new_type: str = None, new_size: str = None) -> ProductResponse:
    by_id = name_or_id.isdigit()
    if by_id:
        product = await Product.get(id=int(name_or_id))
    else:
        product = await Product.get(name=name_or_id)
    if product is None:
        return ProductResponse(meta=MetaData(code=404, message="Product not found"), response=[])
    if new_name is not None:
        product.name = new_name
    if new_description is not None:
        product.description = new_description
    if new_price is not None:
        product.price = new_price
    if new_type is not None:
        product.type = new_type
    if new_size is not None:
        product.size = new_size
    await product.save()
    data_response = ProductCreate(id=product.id, name=product.name, description=product.description, price=product.price, type=product.type, size=product.size)
    return ProductResponse(meta=MetaData(code=201, message="Successfully updated product"), response=[data_response])

async def delete_product(name_or_id: str) -> ProductResponse:
    by_id = name_or_id.isdigit()
    if by_id:
        product = await Product.get(id=int(name_or_id))
    else:
        product = await Product.get(name=name_or_id)
    if product is None:
        return ProductResponse(meta=MetaData(code=404, message="Product not found"), response=[])
    await product.delete()
    return ProductResponse(meta=MetaData(code=204, message="successfully deleted Product"), response=[])

@app.get("/auth")
async def auth(request: Request):
    auth = await google_authorization(
        scopes,
        redirect_auth="https://1e0b-36-72-212-110.ngrok-free.app/auth2callback",
        redirect_complete="https://1e0b-36-72-212-110.ngrok-free.app/auth",
        request=request,
    )
    return RedirectResponse(auth)

@app.get("/auth2callback")
async def auth_callback(request: Request, state):
    auth_call = await google_oauth_cb(
        state=state,
        redirect_uri="https://1e0b-36-72-212-110.ngrok-free.app/auth2callback",
        scopes=scopes,
        request=request,
    )
    return auth_call

@app.get("/")
async def root(request: Request):
    credentials = request.query_params.get("credentials")
    if not credentials:
        raise HTTPException(status_code=400, detail="Credentials not found")
    return JSONResponse({"credentials": credentials})

@app.on_event("startup")
async def startup_event():
    init_db(app)

@app.post("/signup/")
async def signup(create_user_data: UserCreate):
    response = await perform_signup(create_user_data)
    return response

@app.post("/login/")
async def login(user_data: UserLogin):
    response = await perform_login(user_data)
    return response

@app.get("/get_all_product/", response_model=ProductResponse)
async def get_all_product_endpoint():
    return await get_all_product()

@app.post("/create_product/", response_model=ProductResponse)
async def create_product_endpoint(product_request: ProductCreateRequest = Body(...)):
    return await create_product(**product_request.dict())

@app.post("/upload_product_photo/{name_or_id}/", response_model=ProductResponse)
async def upload_product_photo_endpoint(name_or_id: str, product_photo: UploadFile = File(...)):
    return await upload_product_photo(name_or_id, product_photo)

@app.put("/update_product/", response_model=ProductResponse)
async def update_product_endpoint(name_or_id: str, new_name: str = None, new_description: str = None, new_price: float = None, new_type: str = None, new_size: str = None):
    return await update_product(name_or_id, new_name, new_description, new_price, new_type, new_size)

@app.delete("/delete_product/", response_model=ProductResponse)
async def delete_product_endpoint(name_or_id: str):
    return await delete_product(name_or_id)