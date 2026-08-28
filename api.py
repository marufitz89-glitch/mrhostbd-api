import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path

import jwt
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, EmailStr


router = APIRouter()


# =========================================================
# CONFIG
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")
ALGORITHM = "HS256"

DATA_DIR = Path("data")
PROJECT_DIR = Path("projects")

DATA_DIR.mkdir(exist_ok=True)
PROJECT_DIR.mkdir(exist_ok=True)

USERS_FILE = DATA_DIR / "users.json"
PROJECTS_FILE = DATA_DIR / "projects.json"


# =========================================================
# JSON DATABASE HELPERS
# =========================================================

def load_json(file_path: Path, default):
    if not file_path.exists():
        file_path.write_text(
            json.dumps(default, indent=2),
            encoding="utf-8"
        )
        return default

    try:
        return json.loads(
            file_path.read_text(encoding="utf-8")
        )
    except Exception:
        return default


def save_json(file_path: Path, data):
    file_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8"
    )


def load_users():
    return load_json(USERS_FILE, [])


def load_projects():
    return load_json(PROJECTS_FILE, [])


# =========================================================
# PASSWORD
# =========================================================

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        120000
    ).hex()

    return f"{salt}${hashed}"


def verify_password(password: str, stored_password: str) -> bool:
    try:
        salt, stored_hash = stored_password.split("$", 1)

        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            120000
        ).hex()

        return secrets.compare_digest(
            hashed,
            stored_hash
        )

    except Exception:
        return False


# =========================================================
# JWT
# =========================================================

def create_token(user_id: str):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(days=7)
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(authorization: str | None):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization token required"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header"
        )

    token = authorization.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload["user_id"]

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expired"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )


# =========================================================
# MODELS
# =========================================================

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProjectCreate(BaseModel):
    name: str
    description: str = ""


# =========================================================
# REGISTER
# =========================================================

@router.post("/register")
async def register(data: RegisterRequest):

    users = load_users()

    email = data.email.lower().strip()

    if len(data.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters"
        )

    for user in users:
        if user["email"] == email:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )

    user_id = secrets.token_hex(12)

    user = {
        "id": user_id,
        "name": data.name.strip(),
        "email": email,
        "password": hash_password(data.password),
        "role": "user",
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }

    users.append(user)

    save_json(
        USERS_FILE,
        users
    )

    token = create_token(user_id)

    return {
        "success": True,
        "message": "Registration successful",
        "token": token,
        "user": {
            "id": user_id,
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }


# =========================================================
# LOGIN
# =========================================================

@router.post("/login")
async def login(data: LoginRequest):

    users = load_users()

    email = data.email.lower().strip()

    user = next(
        (
            u for u in users
            if u["email"] == email
        ),
        None
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if user.get("status") != "active":
        raise HTTPException(
            status_code=403,
            detail="Account is disabled"
        )

    if not verify_password(
        data.password,
        user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token = create_token(user["id"])

    return {
        "success": True,
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }


# =========================================================
# CURRENT USER
# =========================================================

@router.get("/me")
async def me(
    authorization: str | None = Header(default=None)
):

    user_id = get_current_user(
        authorization
    )

    users = load_users()

    user = next(
        (
            u for u in users
            if u["id"] == user_id
        ),
        None
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "success": True,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"]
        }
    }


# =========================================================
# CREATE PROJECT
# =========================================================

@router.post("/projects")
async def create_project(
    data: ProjectCreate,
    authorization: str | None = Header(default=None)
):

    user_id = get_current_user(
        authorization
    )

    projects = load_projects()

    project_id = secrets.token_hex(10)

    project = {
        "id": project_id,
        "user_id": user_id,
        "name": data.name.strip(),
        "description": data.description.strip(),
        "status": "draft",
        "subdomain": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }

    projects.append(project)

    save_json(
        PROJECTS_FILE,
        projects
    )

    project_path = PROJECT_DIR / project_id

    project_path.mkdir(
        parents=True,
        exist_ok=True
    )

    # Default homepage
    index_file = project_path / "index.html"

    index_file.write_text(
        """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>My MRHostBD Website</title>
</head>
<body>
    <h1>Welcome to MRHostBD</h1>
    <p>Your website is ready.</p>
</body>
</html>
""",
        encoding="utf-8"
    )

    return {
        "success": True,
        "message": "Project created",
        "project": project
    }


# =========================================================
# LIST PROJECTS
# =========================================================

@router.get("/projects")
async def list_projects(
    authorization: str | None = Header(default=None)
):

    user_id = get_current_user(
        authorization
    )

    projects = load_projects()

    user_projects = [
        project
        for project in projects
        if project["user_id"] == user_id
    ]

    return {
        "success": True,
        "projects": user_projects
    }


# =========================================================
# DELETE PROJECT
# =========================================================

@router.delete("/projects/{project_id}")
async def delete_project(
    project_id: str,
    authorization: str | None = Header(default=None)
):

    user_id = get_current_user(
        authorization
    )

    projects = load_projects()

    project = next(
        (
            p for p in projects
            if p["id"] == project_id
            and p["user_id"] == user_id
        ),
        None
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found"
        )

    projects = [
        p for p in projects
        if p["id"] != project_id
    ]

    save_json(
        PROJECTS_FILE,
        projects
    )

    project_path = PROJECT_DIR / project_id

    if project_path.exists():
        import shutil
        shutil.rmtree(project_path)

    return {
        "success": True,
        "message": "Project deleted"
    }


# =========================================================
# API STATUS
# =========================================================

@router.get("/status")
async def api_status():

    return {
        "success": True,
        "service": "MRHostBD API",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat()
    }