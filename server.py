from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import bcrypt
import jwt
import asyncio
import httpx

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]
JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in environment variables")

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Models ---
class UserCreate(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str

class TaskCreate(BaseModel):
    title: str
    taskDate: str
    deadline: Optional[str] = None
    description: Optional[str] = ""
    paymentAmount: Optional[float] = 0
    paymentReceived: Optional[bool] = False

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    taskDate: Optional[str] = None
    deadline: Optional[str] = None
    description: Optional[str] = None
    paymentAmount: Optional[float] = None
    paymentReceived: Optional[bool] = None
    taskCompleted: Optional[bool] = None

class ToggleField(BaseModel):
    field: str
    value: bool

class TaskResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    userId: str
    title: str
    taskDate: str
    deadline: Optional[str] = None
    description: Optional[str] = ""
    paymentAmount: float = 0
    paymentReceived: bool = False
    taskCompleted: bool = False
    createdAt: str
    updatedAt: str

# --- Auth helpers ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc).timestamp() + 86400 * 7
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(authorization: str = None):
    from fastapi import Header
    raise HTTPException(status_code=401, detail="Not authenticated")

from fastapi import Header

async def get_current_user_id(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    payload = decode_token(token)
    return payload["user_id"]


@api_router.get("/health")
async def health():
    return {
        "message": "✅ Server is alive",
        "time": datetime.now(timezone.utc).isoformat(),
    }

# --- Auth Routes ---
@api_router.post("/auth/signup")
async def signup(user: UserCreate):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "id": user_id,
        "email": user.email,
        "name": user.name,
        "password": hash_password(user.password),
        "createdAt": now
    }
    await db.users.insert_one(user_doc)
    token = create_token(user_id, user.email)
    return {"token": token, "user": {"id": user_id, "email": user.email, "name": user.name}}

@api_router.post("/auth/login")
async def login(user: UserLogin):
    existing = await db.users.find_one({"email": user.email}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(user.password, existing["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(existing["id"], existing["email"])
    return {"token": token, "user": {"id": existing["id"], "email": existing["email"], "name": existing["name"]}}

@api_router.get("/auth/me")
async def get_me(user_id: str = Depends(get_current_user_id)):
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# --- Task Routes ---
@api_router.post("/tasks")
async def create_task(task: TaskCreate, user_id: str = Depends(get_current_user_id)):
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    task_doc = {
        "id": task_id,
        "userId": user_id,
        "title": task.title,
        "taskDate": task.taskDate,
        "deadline": task.deadline or "",
        "description": task.description or "",
        "paymentAmount": task.paymentAmount or 0,
        "paymentReceived": task.paymentReceived or False,
        "taskCompleted": False,
        "createdAt": now,
        "updatedAt": now
    }
    await db.tasks.insert_one(task_doc)
    task_doc.pop("_id", None)
    return task_doc

@api_router.get("/tasks")
async def get_tasks(user_id: str = Depends(get_current_user_id)):
    tasks = await db.tasks.find({"userId": user_id}, {"_id": 0}).sort("createdAt", -1).to_list(1000)
    return tasks

@api_router.put("/tasks/{task_id}")
async def update_task(task_id: str, task: TaskUpdate, user_id: str = Depends(get_current_user_id)):
    existing = await db.tasks.find_one({"id": task_id, "userId": user_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Task not found")
    
    update_data = {k: v for k, v in task.model_dump().items() if v is not None}
    update_data["updatedAt"] = datetime.now(timezone.utc).isoformat()
    
    await db.tasks.update_one({"id": task_id}, {"$set": update_data})
    updated = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    return updated

@api_router.patch("/tasks/{task_id}/toggle")
async def toggle_task_field(task_id: str, body: ToggleField, user_id: str = Depends(get_current_user_id)):
    if body.field not in ["paymentReceived", "taskCompleted"]:
        raise HTTPException(status_code=400, detail="Invalid field")
    
    existing = await db.tasks.find_one({"id": task_id, "userId": user_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Task not found")
    
    now = datetime.now(timezone.utc).isoformat()
    await db.tasks.update_one({"id": task_id}, {"$set": {body.field: body.value, "updatedAt": now}})
    updated = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    return updated

@api_router.delete("/tasks/{task_id}")
async def delete_task(task_id: str, user_id: str = Depends(get_current_user_id)):
    existing = await db.tasks.find_one({"id": task_id, "userId": user_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Task not found")
    await db.tasks.delete_one({"id": task_id, "userId": user_id})
    return {"message": "Task deleted"}

@api_router.get("/")
async def root():
    return {"message": "TaskFlow API"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

async def keep_server_alive():
    # Delay so app + DB are fully ready
    await asyncio.sleep(10)

    BASE_URL = os.getenv(
        "BASE_URL",
        "https://your-fastapi-backend.onrender.com"
    )

    HEALTH_URL = f"{BASE_URL}/api/health"

    while True:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                res = await client.get(HEALTH_URL)

            logger.info(
                f"[KeepAlive] ✅ Ping success @ {datetime.now(timezone.utc).isoformat()}"
            )
        except Exception as e:
            logger.error(f"[KeepAlive] ❌ Ping failed: {e}")

        # 5 minutes (same as Node)
        await asyncio.sleep(5 * 60)

@app.on_event("startup")
async def start_keep_alive():
    asyncio.create_task(keep_server_alive())


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
