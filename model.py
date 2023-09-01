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
    password = fields.CharField(max_length=564,null=True)

    class Meta:
        table = "users"
        
    def __str__(self):
        return self.user_id
    
class CartItem(Model):
    id_cart = fields.IntField(pk=True)
    product = fields.ForeignKeyField('models.Product', related_name='cart_items')
    user = fields.ForeignKeyField('models.User', related_name='cart_items')
    quantity = fields.IntField()

    class Meta:
        table = "cart_items"
        
    def __str__(self):
        return self.id_cart