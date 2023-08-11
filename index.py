from fastapi import FastAPI, Body, UploadFile, File
from config import init_db
from body import ProductCreate, ProductResponse, MetaData, ProductCreateRequest, UserCreate, UserLogin
from model import Product, User
from tortoise.exceptions import IntegrityError
import os

app = FastAPI()

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

async def perform_signup(user_data: UserCreate) -> MetaData:
    user_exists = await User.exists(email=user_data.email)
    if user_exists:
        return MetaData(code=400, message="Email already exists")
    try:
        user = await User.create(email=user_data.email, password=user_data.create_password)
        return MetaData(code=201, message="User created successfully", email=user.email)
    except IntegrityError as e:
        return MetaData(code=400, message="Error creating user: IntegrityError")
    except Exception as e:
        return MetaData(code=500, message="Error creating user")

async def perform_signin(user_data: UserLogin) -> MetaData:
    try:
        user = await User.get(email=user_data.email)
    except User.DoesNotExist:
        return MetaData(code=404, message="User not found")
    if user.password != user_data.password:
        return MetaData(code=401, message="Invalid email or password")
    return MetaData(code=200, message="Login successful", email=user.email)

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

@app.post("/signup/")
async def signup(create_user_data: UserCreate):
    response = await perform_signup(create_user_data)
    return response

@app.post("/signin/")
async def signin(user_data: UserLogin):
    response = await perform_signin(user_data)
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
