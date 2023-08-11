from tortoise import fields
from tortoise.models import Model

class Product(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)
    description = fields.CharField(max_length=255)
    price = fields.DecimalField(max_digits=50, decimal_places=2)
    type = fields.CharField(max_length=50)
    size = fields.CharField(max_length=10)

    class Meta:
        table = "products"

class User(Model):
    id = fields.IntField(pk=True)
    email = fields.CharField(max_length=100, unique=True)
    password = fields.CharField(max_length=255) 
    
    class Meta:
        table = "users"
        
    def __str__(self):
        return self.id