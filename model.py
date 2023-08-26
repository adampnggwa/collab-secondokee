from tortoise import fields
from tortoise.models import Model

class Product(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)
    brand = fields.CharField(max_length=100)
    description = fields.CharField(max_length=255)
    price = fields.DecimalField(max_digits=50, decimal_places=2)
    type = fields.CharField(max_length=50)
    size = fields.CharField(max_length=10)
    stock = fields.IntField()

    class Meta:
        table = "products"

    def __str__(self):
        return self.id

class User(Model):
    user_id = fields.IntField(pk=True)
    email = fields.CharField(max_length=100, unique=True)
    token = fields.CharField(max_length=500, null=True)
    waktu_basi = fields.DatetimeField(null=True)
    status = fields.BooleanField(default=False)

    class Meta:
        table = "users"
        
    def __str__(self):
        return self.user_id
    
class UserData(Model):
    id_user = fields.IntField(pk=True)
    email = fields.CharField(max_length=100)
    password = fields.CharField(max_length=564)

    class Meta:
        table = "user_data"

    def __str__(self):
        return self.id_user