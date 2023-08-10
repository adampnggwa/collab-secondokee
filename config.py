from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise

TORTOISE_ORM = {
    "connections": {
        "default": "mysql://root:@127.0.0.1/secondokee",
    },
    "apps": {
        "models": {
            "models":["model", "aerich.models"],
            "default_connection": "default",
        },
    },
}

def init_db(app: FastAPI) -> None:
    register_tortoise(
        app,
        db_url="mysql://root:@127.0.0.1/secondokee",
        modules={"models": [
            "model"
        ]},
        generate_schemas=True,
        add_exception_handlers=True,
    )
