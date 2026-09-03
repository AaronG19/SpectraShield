"""Database engine, session factory, and FastAPI dependency."""
try:
    from config import DATABASE_URL
except ImportError:
    try:
        from backend.config import DATABASE_URL
    except ImportError:
        DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/agent_security"

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker, declarative_base

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
