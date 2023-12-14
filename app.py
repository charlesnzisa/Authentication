from fastapi import Depends, FastAPI, HTTPException, status, Cookie
from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from databases import Database
from sqlalchemy import create_engine, Column, String, Integer, MetaData, Table
from sqlalchemy.sql import select
from starlette.requests import Request
from starlette.responses import JSONResponse

app = FastAPI()

# SQLite database configuration
DATABASE_URL = "sqlite:///./test.db"
database = Database(DATABASE_URL)

metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("github_id", String, unique=True, index=True),
    Column("access_token", String),
)

engine = create_engine(DATABASE_URL)
metadata.create_all(bind=engine)

# OAuth 2.0 Authorization Code Bearer scheme configuration
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    tokenUrl="token",
    authorizationUrl="authorize",
)

# OAuth provider configuration (GitHub as an example)
oauth = OAuth()

oauth.register(
    name='github',
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    authorize_client_params=None,
    token_url='https://github.com/login/oauth/access_token',
    token_params=None,
    redirect_uri='http://localhost:8000/login/callback',
    client_kwargs={'scope': 'user'},
)

# Connect to the database
@app.on_event("startup")
async def startup_db():
    await database.connect()

# Disconnect from the database
@app.on_event("shutdown")
async def shutdown_db():
    await database.disconnect()

# Example protected endpoint
@app.get("/protected-data")
async def get_protected_data(token: str = Depends(oauth2_scheme)):
    """
    Example of a protected endpoint that requires OAuth 2.0 Authorization Code Bearer token.
    """
    user_info = await get_user_info(token)
    return {"message": "You have access to protected data!", "user_info": user_info}

# Helper function to get user information from GitHub API
async def get_user_info(token: str):
    user_url = "https://api.github.com/user"
    headers = {"Authorization": f"Bearer {token}"}

    async with app.httpx_client.get(user_url, headers=headers) as response:
        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch user information")

# Redirect endpoint for initiating the authorization process
@app.get("/login")
async def login_with_github(request: Request):
    """
    Redirects the user to the GitHub authorization URL to initiate the OAuth 2.0 authorization process.
    """
    redirect_uri = request.url_for("login_callback")
    return await oauth.github.authorize_redirect(request, redirect_uri)

# Callback endpoint for handling the redirection after GitHub authorization
@app.route("/login/callback")
async def login_callback(request: Request, code: str = None, state: str = None, session: str = Cookie(None)):
    """
    Callback endpoint where GitHub redirects the user after successful authorization.
    Exchanges the authorization code for an access token.
    """
    token = await oauth.github.authorize_access_token(request)

    # Check if the user is already logged in
    if session:
        return JSONResponse(content={"message": "User is already logged in", "access_token": session})

    # Check if the user already exists in the database
    user = await database.fetch_one(select(users_table).where(users_table.c.github_id == str(token["github_id"])))

    # If the user doesn't exist, create a new user
    if not user:
        user = await database.execute(users_table.insert().values(github_id=str(token["github_id"]), access_token=token["access_token"]))

    # Store the user's GitHub ID in the session cookie
    response = JSONResponse(content={"message": "Successfully authenticated with GitHub", "access_token": token["access_token"]})
    response.set_cookie(key="session", value=str(user["github_id"]))
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
