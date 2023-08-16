
class MetaData:
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message

def success_response(code: int, message: str) -> dict:
    return {"meta": MetaData(code, message), "response": "success"}

def error_response(code: int, message: str) -> dict:
    return {"meta": MetaData(code, message), "response": "error"}
