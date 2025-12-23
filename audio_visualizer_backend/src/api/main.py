import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor

# App metadata and OpenAPI tags for better documentation
app = FastAPI(
    title="Audio Visualizer API",
    description="Backend service for authentication and storing audio visualizer configurations.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Health", "description": "Service health and diagnostics"},
        {"name": "Auth", "description": "User authentication and session management"},
        {"name": "Users", "description": "User profile and management endpoints"},
        {"name": "Visualizer", "description": "Store and retrieve audio visualizer configurations"},
        {"name": "WebSockets", "description": "WebSocket usage notes and endpoints (if any in future)"},
    ],
)

# CORS for frontend local dev (React on 3000)
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000,https://vscode-internal-25821-qa.qa01.cloud.kavia.ai:3000")
allow_origins = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= ENV VARS (These must be set by orchestrator in .env) =========
# JWT settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_DEV_ONLY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

# Database: Must come from database container env
# Required envs: POSTGRES_URL or POSTGRES_USER/PASSWORD/DB/HOST/PORT
POSTGRES_URL = os.getenv("POSTGRES_URL")
if not POSTGRES_URL:
    # Build from parts if full URL isn't provided
    POSTGRES_USER = os.getenv("POSTGRES_USER", "")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")
    POSTGRES_DB = os.getenv("POSTGRES_DB", "")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
    if POSTGRES_USER and POSTGRES_DB:
        POSTGRES_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ---------- Database Helpers ----------
def _get_db():
    """
    Internal helper to create a new DB connection.
    Connections are short-lived per request.
    """
    if not POSTGRES_URL:
        raise RuntimeError("Database connection info not configured. Ensure POSTGRES_URL or parts are set in .env.")
    conn = psycopg2.connect(POSTGRES_URL, cursor_factory=RealDictCursor)
    return conn


def _init_db():
    """
    Initialize database schema if not exists.
    """
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        display_name TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS visualizer_configs (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name TEXT NOT NULL,
                        config JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
    finally:
        conn.close()


# Initialize schema on startup
@app.on_event("startup")
def on_startup():
    _init_db()


# ---------- Security Utilities ----------
def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


# ---------- Pydantic Models ----------
class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type")


class TokenData(BaseModel):
    user_id: Optional[int] = Field(None, description="User ID from token subject")


class SignupRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=6, description="Password (min 6 chars)")
    display_name: Optional[str] = Field(None, description="Display name")


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    display_name: Optional[str] = None
    created_at: datetime


class UpdateProfileRequest(BaseModel):
    display_name: Optional[str] = Field(None, description="New display name")


class VisualizerConfigCreate(BaseModel):
    name: str = Field(..., description="Configuration name")
    config: dict = Field(..., description="Arbitrary JSON configuration for visualizer")


class VisualizerConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, description="Optional new name")
    config: Optional[dict] = Field(None, description="Optional new configuration")


class VisualizerConfigOut(BaseModel):
    id: int
    user_id: int
    name: str
    config: dict
    created_at: datetime
    updated_at: datetime


# ---------- User helpers ----------
def _get_user_by_email(email: str) -> Optional[dict]:
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
                row = cur.fetchone()
                return dict(row) if row else None
    finally:
        conn.close()


def _get_user_by_id(user_id: int) -> Optional[dict]:
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
                row = cur.fetchone()
                return dict(row) if row else None
    finally:
        conn.close()


def _create_user(email: str, password: str, display_name: Optional[str]) -> dict:
    if _get_user_by_email(email):
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = get_password_hash(password)
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (email, password_hash, display_name) VALUES (%s, %s, %s) RETURNING *;",
                    (email, password_hash, display_name),
                )
                user = cur.fetchone()
                return dict(user)
    finally:
        conn.close()


def _authenticate_user(email: str, password: str) -> Optional[dict]:
    user = _get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


# ---------- Dependency ----------
def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    PUBLIC_INTERFACE
    """
    """Extract current user from JWT token and return user dict.

    Parameters:
        token (str): OAuth2 bearer token injected by FastAPI.

    Returns:
        dict: Database row for the authenticated user.

    Raises:
        HTTPException: If token invalid or user not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        subject: Optional[str] = payload.get("sub")
        if subject is None:
            raise credentials_exception
        user_id = int(subject)
    except JWTError:
        raise credentials_exception
    user = _get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user


# ---------- Routes ----------

# PUBLIC_INTERFACE
@app.get("/", tags=["Health"], summary="Health Check", description="Simple health check endpoint.")
def health_check():
    """Health check endpoint.

    Returns:
        dict: Message indicating service is up.
    """
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/auth/signup", response_model=UserResponse, tags=["Auth"], summary="User signup")
def signup(payload: SignupRequest):
    """Register a new user.

    Body:
        email (EmailStr): user email
        password (str): password, min 6
        display_name (str, optional): display name

    Returns:
        UserResponse: created user
    """
    user = _create_user(payload.email, payload.password, payload.display_name)
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user.get("display_name"),
        "created_at": user["created_at"],
    }

# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=Token, tags=["Auth"], summary="User login (OAuth2 Password)")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and obtain an access token.

    Form fields:
        username (str): email
        password (str): password

    Returns:
        Token: access token and token type
    """
    user = _authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": str(user["id"])})
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@app.get("/users/me", response_model=UserResponse, tags=["Users"], summary="Get current user profile")
def get_me(current_user: dict = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "display_name": current_user.get("display_name"),
        "created_at": current_user["created_at"],
    }

# PUBLIC_INTERFACE
@app.patch("/users/me", response_model=UserResponse, tags=["Users"], summary="Update current user profile")
def update_me(update: UpdateProfileRequest, current_user: dict = Depends(get_current_user)):
    """Update the current user's profile. Only display_name is supported."""
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET display_name = COALESCE(%s, display_name) WHERE id = %s RETURNING *;",
                    (update.display_name, current_user["id"]),
                )
                row = cur.fetchone()
                return {
                    "id": row["id"],
                    "email": row["email"],
                    "display_name": row.get("display_name"),
                    "created_at": row["created_at"],
                }
    finally:
        conn.close()

# PUBLIC_INTERFACE
@app.post(
    "/visualizer/configs",
    response_model=VisualizerConfigOut,
    tags=["Visualizer"],
    summary="Create visualizer configuration",
    description="Store a new visualizer configuration for the current user."
)
def create_config(payload: VisualizerConfigCreate, current_user: dict = Depends(get_current_user)):
    """Create a visualizer configuration owned by the current user."""
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO visualizer_configs (user_id, name, config)
                    VALUES (%s, %s, %s)
                    RETURNING *;
                    """,
                    (current_user["id"], payload.name, jsonify(payload.config)),
                )
                row = cur.fetchone()
                return normalize_config_row(row)
    finally:
        conn.close()

# PUBLIC_INTERFACE
@app.get(
    "/visualizer/configs",
    response_model=List[VisualizerConfigOut],
    tags=["Visualizer"],
    summary="List visualizer configurations",
    description="List all visualizer configurations owned by the current user."
)
def list_configs(current_user: dict = Depends(get_current_user)):
    """List the current user's visualizer configurations."""
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM visualizer_configs WHERE user_id = %s ORDER BY updated_at DESC;",
                    (current_user["id"],),
                )
                rows = cur.fetchall() or []
                return [normalize_config_row(r) for r in rows]
    finally:
        conn.close()

# PUBLIC_INTERFACE
@app.get(
    "/visualizer/configs/{config_id}",
    response_model=VisualizerConfigOut,
    tags=["Visualizer"],
    summary="Get a visualizer configuration by ID"
)
def get_config(config_id: int, current_user: dict = Depends(get_current_user)):
    """Retrieve a specific configuration owned by the current user."""
    row = _get_config_owned(current_user["id"], config_id)
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    return normalize_config_row(row)

# PUBLIC_INTERFACE
@app.patch(
    "/visualizer/configs/{config_id}",
    response_model=VisualizerConfigOut,
    tags=["Visualizer"],
    summary="Update a visualizer configuration"
)
def update_config(config_id: int, update: VisualizerConfigUpdate, current_user: dict = Depends(get_current_user)):
    """Update fields on a configuration owned by the current user."""
    existing = _get_config_owned(current_user["id"], config_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Config not found")

    new_name = update.name if update.name is not None else existing["name"]
    new_config = update.config if update.config is not None else existing["config"]

    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE visualizer_configs
                    SET name = %s, config = %s, updated_at = NOW()
                    WHERE id = %s
                    RETURNING *;
                    """,
                    (new_name, jsonify(new_config), config_id),
                )
                row = cur.fetchone()
                return normalize_config_row(row)
    finally:
        conn.close()

# PUBLIC_INTERFACE
@app.delete(
    "/visualizer/configs/{config_id}",
    status_code=204,
    tags=["Visualizer"],
    summary="Delete a visualizer configuration"
)
def delete_config(config_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a configuration owned by the current user."""
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM visualizer_configs WHERE id = %s AND user_id = %s;",
                    (config_id, current_user["id"]),
                )
                # If nothing deleted, it either didn't exist or not owned - return 204 regardless
                return
    finally:
        conn.close()


# ---------- Helpers for JSON/rows ----------
import json as _json  # alias to avoid shadowing pydantic BaseModel

def jsonify(value) -> str:
    """Serialize a Python value to a JSON string for DB storage."""
    return _json.dumps(value)

def normalize_config_row(row: dict) -> dict:
    """Convert DB row to response dict with parsed JSON."""
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "name": row["name"],
        "config": row["config"] if isinstance(row["config"], dict) else _json.loads(row["config"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _get_config_owned(user_id: int, config_id: int) -> Optional[dict]:
    conn = _get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM visualizer_configs WHERE id = %s AND user_id = %s;",
                    (config_id, user_id),
                )
                row = cur.fetchone()
                return dict(row) if row else None
    finally:
        conn.close()
