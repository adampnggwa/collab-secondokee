from fastapi import FastAPI, Body, UploadFile, File, Request, HTTPException, Query
from body import ProductCreate, ProductResponse, MetaData, ProductCreateRequest, UserSignin, UserSignup
from helper import credentials_to_dict, user_response, create_token, check_token_expired
from fastapi.responses import JSONResponse, RedirectResponse
from tortoise.exceptions import IntegrityError
from model import Product, User, UserData
import google_auth_oauthlib.flow
from database import init_db
import requests
import secrets
import hashlib
import os

app = FastAPI(title="Second-Okee")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

@app.on_event("startup")
async def startup_event():
    init_db(app)

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

async def perform_signup(user_data: UserSignup) -> dict:
    try:
        user_exists = await UserData.exists(email=user_data.email)
        if user_exists:
            return {"status": "error", "code": 400, "message": "Email already exists"}
        salt = secrets.token_hex(16)
        hashed_password = hash_password(user_data.create_password, salt)
        user = await UserData.create(email=user_data.email, password=hashed_password + salt)
        return {"status": "success", "code": 201, "message": "User created successfully"}
    except IntegrityError as e:
        return {"status": "error", "code": 400, "message": "Error creating user: Email already exists"}
    except Exception as e:
        return {"status": "error", "code": 500, "message": "Error creating user: Internal Server Error"}

async def perform_login(user_data: UserSignin) -> dict:
    try:
        user = await UserData.get(email=user_data.email)
    except UserData.DoesNotExist:
        return {"status": "error", "code": 404, "message": "User not found"}
    salt = user.password[-32:]
    hashed_input_password = hash_password(user_data.password, salt)
    if user.password[:-32] != hashed_input_password:
        return {"status": "error", "code": 400, "message": "Invalid email or password"}
    return {"status": "success", "code": 200, "message": "Login successful"}

async def create_product(name: str, brand: str, description: str, price: float, type: str, size: str, stock: int) -> ProductResponse:
    product = await Product.create(name=name, brand=brand, description=description, price=price, type=type, size=size, stock=stock)
    data_response = ProductCreate(id=product.id, name=product.name, brand=product.brand, description=product.description, price=product.price, type=product.type, size=product.size, stock=product.stock)
    return ProductResponse(meta=MetaData(code=201, message="successfully added product"), response=[data_response])

async def get_all_product() -> ProductResponse:
    all_product = await Product.all()
    response_data = [ProductCreate(id=product.id, name=product.name, brand=product.brand, description=product.description, price=product.price, type=product.type, size=product.size, stock=product.stock) for product in all_product]
    return ProductResponse(meta=MetaData(code=200, message="successfully displayed all products"), response=response_data)
    
async def search_products(name: str = None, min_price: float = None, max_price: float = None, product_type: str = None):
    filters = {}
    if name:
        filters['name__icontains'] = name
    if min_price is not None:
        filters['price__gte'] = min_price
    if max_price is not None:
        filters['price__lte'] = max_price
    if product_type:
        filters['type__iexact'] = product_type
    filtered_products = await Product.filter(**filters)
    if not filtered_products:
        return ProductResponse(meta=MetaData(code=404, message="No products found matching the criteria"), response=[])
    response_data = [
        ProductCreate(
            id=product.id,
            name=product.name,
            brand=product.brand,
            description=product.description,
            price=product.price,
            type=product.type,
            size=product.size,
            stock=product.stock
        )
        for product in filtered_products
    ]
    return ProductResponse(meta=MetaData(code=200, message="Products found matching the criteria"), response=response_data)

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

async def update_product(name_or_id: str, new_name: str = None, new_brand: str = None, new_description: str = None, new_price: float = None, new_type: str = None, new_size: str = None, new_stock: int = None) -> ProductResponse:
    by_id = name_or_id.isdigit()
    if by_id:
        product = await Product.get(id=int(name_or_id))
    else:
        product = await Product.get(name=name_or_id)
    if product is None:
        return ProductResponse(meta=MetaData(code=404, message="Product not found"), response=[])
    if new_name is not None:
        product.name = new_name
    if new_brand is not None:
        product.brand = new_brand
    if new_description is not None:
        product.description = new_description
    if new_price is not None:
        product.price = new_price
    if new_type is not None:
        product.type = new_type
    if new_size is not None:
        product.size = new_size
    if new_stock is not None:
        product.stock = new_stock
    await product.save()
    data_response = ProductCreate(id=product.id, name=product.name, brand=product.brand, description=product.description, price=product.price, type=product.type, size=product.size, stock=product.stock)
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

@app.post("/signup/")
async def signup(create_user_data: UserSignup):
    response = await perform_signup(create_user_data)
    return response

@app.post("/signin/")
async def signin(user_data: UserSignin):
    response = await perform_login(user_data)
    return response

@app.get("/verify-token")
async def verify_token(token: str = Query(...)):
    user = await User.filter(token=token).first()
    if user:
        if await check_token_expired(user):
            return RedirectResponse("https://f5b2-202-152-141-19.ngrok-free.app/login")
        else:
            return RedirectResponse("https://f5b2-202-152-141-19.ngrok-free.app/docs")
    else:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.get("/register_google")
async def daftar():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['email', 'profile']  
    )
    flow.redirect_uri = "https://f5b2-202-152-141-19.ngrok-free.app/auth2callbackRegister"
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    return RedirectResponse(authorization_url)

@app.get("/login_google")
async def masuk():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['email', 'profile']  
    )
    flow.redirect_uri = "https://f5b2-202-152-141-19.ngrok-free.app/auth2callbackLogin"
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    return RedirectResponse(authorization_url)

@app.get("/auth2callbackRegister")
async def auth2callback_register(request: Request, state: str):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['email', 'profile'],  
        state=state
    )
    flow.redirect_uri = "https://f5b2-202-152-141-19.ngrok-free.app/auth2callbackRegister"
    authorization_response = str(request.url)
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    access_token = credentials.token

    userinfo_endpoint = 'https://www.googleapis.com/oauth2/v3/userinfo'
    user_info_response = requests.get(userinfo_endpoint, headers={'Authorization': f'Bearer {access_token}'})
    user_info = user_info_response.json()
    email = user_info.get("email")
    nama = user_info.get("name")

    existing_user = await User.filter(email=email).first()
    if not existing_user:
        save = User(nama=nama, email=email, status=True)
        await save.save()
        user = await User.filter(email=email).first()
        await create_token(user)
        response = user_response(user)
        return JSONResponse(response, status_code=201)
    else:
        raise HTTPException(status_code=400, detail="Invalid")
    
@app.get("/auth2callbackLogin")
async def auth2callback(request: Request, state: str):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['email', 'profile'],  
        state=state
    )
    flow.redirect_uri = "https://f5b2-202-152-141-19.ngrok-free.app/auth2callbackLogin"
    authorization_response = str(request.url)
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    creds = credentials_to_dict(credentials)
    access_token = credentials.token

    userinfo_endpoint = 'https://www.googleapis.com/oauth2/v3/userinfo'
    user_info_response = requests.get(userinfo_endpoint, headers={'Authorization': f'Bearer {access_token}'})
    user_info = user_info_response.json()
    email = user_info.get("email")

    existing_user = await User.filter(email=email).first()
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid")
    else:
        user = await User.filter(email=email).first()
        await create_token(user)
        response = user_response(user)
        return JSONResponse(response, status_code=200)

@app.post("/create_product/", response_model=ProductResponse)
async def create_product_endpoint(product_request: ProductCreateRequest = Body(...)):
    return await create_product(**product_request.dict())

@app.get("/get_all_product/", response_model=ProductResponse)
async def get_all_product_endpoint():
    return await get_all_product()

@app.get("/search_products/", response_model=ProductResponse)
async def search_products_endpoint(name: str = None, min_price: float = None, max_price: float = None, product_type: str = None):
    return await search_products(name, min_price, max_price, product_type)

@app.post("/upload_product_photo/{name_or_id}/", response_model=ProductResponse)
async def upload_product_photo_endpoint(name_or_id: str, product_photo: UploadFile = File(...)):
    return await upload_product_photo(name_or_id, product_photo)

@app.put("/update_product/", response_model=ProductResponse)
async def update_product_endpoint(name_or_id: str, new_name: str = None, new_brand: str = None, new_description: str = None, new_price: float = None, new_type: str = None, new_size: str = None, new_stock: int = None):
    return await update_product(name_or_id, new_name, new_brand, new_description, new_price, new_type, new_size, new_stock)

@app.delete("/delete_product/", response_model=ProductResponse)
async def delete_product_endpoint(name_or_id: str):
    return await delete_product(name_or_id)