"""Auth routes: register, login, claim-agent, me."""
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from schemas.auth import UserRegister, UserLogin, ClaimAgentRequest
from authentication.dependencies import (
    hash_password, verify_password, create_access_token, get_current_user,
)

router = APIRouter(tags=["auth"])


@router.post("/auth/register")
async def register_user(data: UserRegister, db: DBSession = Depends(get_db)):
    email = data.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email address")
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer", "user_id": user.id, "email": user.email}


@router.post("/auth/login")
async def login(data: UserLogin, db: DBSession = Depends(get_db)):
    email = data.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer", "user_id": user.id, "email": user.email}


@router.post("/auth/claim-agent")
async def claim_agent(
    data: ClaimAgentRequest,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    """Link a freshly-registered agent to the logged-in user's account
    using the one_time_token the agent received at /api/agents/register."""
    hostname = data.hostname.strip().lower()
    agent = db.query(Agent).filter(func.lower(Agent.hostname) == hostname).order_by(Agent.registered_at.desc()).first()
    if not agent:
        raise HTTPException(status_code=404, detail="No agent found with that hostname")
    if agent.owner_id:
        raise HTTPException(status_code=409, detail="This agent is already claimed by a user")
    if not agent.one_time_token or not secrets.compare_digest(agent.one_time_token, data.one_time_token):
        raise HTTPException(status_code=403, detail="Invalid one-time token")
    agent.owner_id = current_user.id
    agent.one_time_token = ""
    db.commit()
    return {"message": "Agent claimed successfully", "agent_id": agent.id, "hostname": agent.hostname}


@router.get("/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {"user_id": current_user.id, "email": current_user.email, "created_at": current_user.created_at.isoformat()}
