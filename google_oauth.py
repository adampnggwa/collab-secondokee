import os
import json
import requests
import google_auth_oauthlib.flow
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import RedirectResponse
from starlette.requests import Request

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
CLIENT_SECRETS_FILE = 'C:\\adampkl\\secondokee\\secrets\\credentials.json'
async def google_authorization(
    scopes, redirect_auth, redirect_complete, request: Request
):
    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes
        )
    except FileNotFoundError as e:
        print(f"Error opening {CLIENT_SECRETS_FILE}: {e}")
        return None
    flow.redirect_uri = redirect_auth
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
    )
    return authorization_url

async def google_auth_callback(redirect_uri, scopes, request: Request):
    scp = " ".join(scopes)
    auth_uri = (
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code"
        "&client_id={}&redirect_uri={}&scope={}"
    ).format(
        "705038998148-ahmomgi3blaukc1r9acmirgr3ff6g3in.apps.googleusercontent.com",
        redirect_uri,
        scp
    )
    if "code" not in request.query_params:
        return RedirectResponse(auth_uri)
    else:
        auth_code = request.query_params.get("code")
        data = {
            "code": auth_code,
            "client_id": "705038998148-ahmomgi3blaukc1r9acmirgr3ff6g3in.apps.googleusercontent.com",
            "client_secret": "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",
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        r = requests.post("https://oauth2.googleapis.com/token", data=data)
        return r.json()
    
def credentials_to_dict(credentials):
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
        }

async def google_oauth_cb(state, redirect_uri, scopes, request: Request):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        client_secrets_file=CLIENT_SECRETS_FILE, scopes=scopes, state=state
        )
    flow.redirect_uri = redirect_uri
    auth_response = str(request.url)
    flow.fetch_token(authorization_response=auth_response)
    credentials = flow.credentials
    creds = credentials_to_dict(credentials)
    return creds