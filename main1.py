from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
import jwt
from passlib.hash import bcrypt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# FastAPI setup
app = FastAPI(title="To-Do List API")


MONGO_URI = os.getenv("mongodb+srv://rasikadehankar2912:Dehankar%402912@cluster0.xzmmx.mongodb.net")
client =AsyncIOMotorClient("mongodb+srv://rasikadehankar2912:Dehankar%402912@cluster0.xzmmx.mongodb.net")
db = client.todolist

# Security and authentication
SECRET_KEY = os.getenv("SECRET_KEY", "mysecret")
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Helper to convert MongoDB ObjectId
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


# Models
class User(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id")
    username: str
    email: EmailStr
    password: str
    role: str = "user"

    class Config:
        json_encoders = {ObjectId: str}


class Task(BaseModel):
    id: Optional[PyObjectId]  #= Field(alias="_id")
    title: str
    description: Optional[str]
    priority: Optional[str] = "medium"
    deadline: Optional[datetime]
    user_id: Optional[str]

    class Config:
        json_encoders = {ObjectId: str}


# Helper: Get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = await db.users.find_one({"_id": ObjectId(payload["user_id"])})
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User(**user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Helper: Role-based access control
async def admin_only(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return current_user


# User registration
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


@app.post("/register")
async def register_user(user: UserRegister):
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = bcrypt.hash(user.password)
    user_data = {"username": user.username, "email": user.email, "password": hashed_password, "role": "user"}
    await db.users.insert_one(user_data)
    return {"message": "User registered successfully"}


# User login
class UserLogin(BaseModel):
    email: EmailStr
    password: str


@app.post("/login")
async def login_user(user: UserLogin):
    db_user = await db.users.find_one({"email": user.email})
    if not db_user or not bcrypt.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"user_id": str(db_user["_id"]), "role": db_user["role"]}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


# Task CRUD endpoints
@app.post("/tasks")
async def create_task(task: Task, current_user: User = Depends(get_current_user)):
    task_data = task.dict()
    task_data["user_id"] = str(current_user.id)
    task_data["deadline"] = task.deadline.isoformat() if task.deadline else None
    result = await db.tasks.insert_one(task_data)
    return {"id": str(result.inserted_id)}



@app.get("/tasks")
async def list_tasks(current_user: User = Depends(get_current_user)):
    tasks = await db.tasks.find({"user_id": str(current_user.id)}).to_list(100)
    for task in tasks:
        print(task)  # Inspect the MongoDB data
        task["id"] = str(task["_id"])  # Map _id to id
    return tasks


@app.get("/tasks/{task_id}")
async def get_task(task_id: str, current_user: User = Depends(get_current_user)):
    task = await db.tasks.find_one({"_id": ObjectId(task_id), "user_id": str(current_user.id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.put("/tasks/{task_id}")
async def update_task(task_id: str, task: Task, current_user: User = Depends(get_current_user)):
    task_data = task.dict(exclude_unset=True)
    if "deadline" in task_data:
        task_data["deadline"] = task_data["deadline"].isoformat()
    result = await db.tasks.update_one({"_id": ObjectId(task_id), "user_id": str(current_user.id)}, {"$set": task_data})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task updated successfully"}


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str, current_user: User = Depends(get_current_user)):
    result = await db.tasks.delete_one({"_id": ObjectId(task_id), "user_id": str(current_user.id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted successfully"}
