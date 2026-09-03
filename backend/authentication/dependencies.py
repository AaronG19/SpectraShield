"""Authentication and authorization dependencies."""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert
from models.events import Application, NetworkConnection

try:
    from config import SECRET_KEY
except ImportError:
    try:
        from backend.config import SECRET_KEY
    except ImportError:
        SECRET_KEY = "default-secret-key-change-in-production"

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24  # 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or ":" not in stored:
        return False
    salt, stored_hash = stored.split(":", 1)
    computed = hashlib.sha256((salt + password).encode()).hexdigest()
    return secrets.compare_digest(computed, stored_hash)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: DBSession = Depends(get_db),
) -> User:
    """Authenticates a human dashboard user via JWT."""
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


async def get_optional_user(
    token: str = Depends(oauth2_scheme),
    db: DBSession = Depends(get_db),
) -> Optional[User]:
    if not token:
        return None
    user_id = decode_access_token(token)
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def get_owned_agent(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
) -> Agent:
    """Use on /api/agents/{agent_id}/... dashboard routes. Confirms the
    logged-in user actually owns the agent referenced in the URL path."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.owner_id is not None and agent.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="You do not have access to this agent")
    return agent


def verify_agent_self(
    agent_id: str,
    x_agent_token: str = Header(default=""),
    db: DBSession = Depends(get_db),
) -> Agent:
    """Use on /api/agents/{agent_id}/.../report routes — these are called
    by the AGENT itself reporting its own telemetry, not by a human user.
    No human JWT is required here, but the agent MUST present the secret
    agent_token it received at registration via the X-Agent-Token header.
    This prevents anyone who merely knows/guesses a valid agent_id from
    spoofing telemetry on that agent's behalf."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not agent.agent_token:
        # Agents registered before this fix was deployed have no token yet —
        # allow once, but this is a temporary migration shim, not a security model.
        return agent
    if not x_agent_token or not secrets.compare_digest(x_agent_token, agent.agent_token):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Agent-Token header")
    return agent


# ---------------------------------------------------------------------------
# Security score calculation
# ---------------------------------------------------------------------------

def calculate_security_score(
    db: DBSession,
    agent: Agent = None,
    user: User = None,
) -> float:
    if agent:
        total_alerts = db.query(func.count(Alert.id)).filter(Alert.agent_id == agent.id).scalar() or 0
        open_alerts = db.query(func.count(Alert.id)).filter(Alert.agent_id == agent.id, Alert.status == "open").scalar() or 0
        critical_alerts = db.query(func.count(Alert.id)).filter(Alert.agent_id == agent.id, Alert.severity == "critical").scalar() or 0
        agents = [agent]
        unapproved = db.query(func.count(Application.id)).filter(Application.agent_id == agent.id, Application.is_approved == False).scalar() or 0
        suspicious_connections = db.query(func.count(NetworkConnection.id)).filter(NetworkConnection.agent_id == agent.id, NetworkConnection.is_suspicious == True).scalar() or 0
    elif user:
        agents = db.query(Agent).filter(Agent.owner_id == user.id).all()
        agent_ids = [a.id for a in agents]
        total_alerts = db.query(func.count(Alert.id)).filter(Alert.agent_id.in_(agent_ids)).scalar() or 0
        open_alerts = db.query(func.count(Alert.id)).filter(Alert.agent_id.in_(agent_ids), Alert.status == "open").scalar() or 0
        critical_alerts = db.query(func.count(Alert.id)).filter(Alert.agent_id.in_(agent_ids), Alert.severity == "critical").scalar() or 0
        unapproved = db.query(func.count(Application.id)).filter(Application.agent_id.in_(agent_ids), Application.is_approved == False).scalar() or 0
        suspicious_connections = db.query(func.count(NetworkConnection.id)).filter(NetworkConnection.agent_id.in_(agent_ids), NetworkConnection.is_suspicious == True).scalar() or 0
    else:
        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "open").scalar() or 0
        critical_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0
        agents = db.query(Agent).all()
        unapproved = db.query(func.count(Application.id)).filter(Application.is_approved == False).scalar() or 0
        suspicious_connections = db.query(func.count(NetworkConnection.id)).filter(NetworkConnection.is_suspicious == True).scalar() or 0

    total_agents = len(agents)
    online_agents = sum(1 for a in agents if a.status == "online")
    tamper_protected = sum(1 for a in agents if a.tamper_protection)
    firewall_enabled_count = sum(1 for a in agents if a.firewall_enabled)
    bitlocker_count = sum(1 for a in agents if a.bitlocker_enabled)

    score = 100.0
    if total_agents > 0:
        online_ratio = online_agents / total_agents
        if online_ratio < 1.0:
            score -= (1.0 - online_ratio) * 15
    score -= open_alerts * 1.5
    score -= critical_alerts * 3.0
    if total_agents > 0:
        score -= (1.0 - (tamper_protected / total_agents)) * 10
        score -= (1.0 - (firewall_enabled_count / total_agents)) * 8
        score -= (1.0 - (bitlocker_count / total_agents)) * 5
    score -= unapproved * 1.0
    score -= suspicious_connections * 2.0
    score = max(0, min(100, score))
    return round(score, 1)
