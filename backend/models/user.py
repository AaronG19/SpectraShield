"""User and Session ORM models."""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from db.base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    agents = relationship("Agent", back_populates="owner")


class SessionRecord(Base):
    """Named SessionRecord to avoid collision with sqlalchemy.orm.Session."""
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    hostname = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
