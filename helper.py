import secrets
import pytz
from datetime import datetime, timedelta

def credentials_to_dict(credentials):
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }
    
def user_response(user):
    response = {
        "user_id": str(user.user_id),
        "email": user.email,
        "token": str(user.token),
        "waktu_basi": str(user.waktu_basi),
        "status": user.status
    }        
    return response

async def create_token(user):
    token = secrets.token_hex(16)
    waktu_basi = datetime.now(pytz.utc) + timedelta(hours=8)
    user.token = token
    user.waktu_basi = waktu_basi
    await user.save()

async def check_token_expired(user):
    current_time = datetime.now(pytz.utc)
    if user.waktu_basi <= current_time:
        user.token = None
        await user.save()
        return True
    return False