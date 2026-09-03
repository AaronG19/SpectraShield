"""Application lifespan: DB table creation and default policy seeding."""
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from sqlalchemy import func

from db.base import Base, engine, SessionLocal
from core.logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Import models so their tables are registered with Base.metadata
    import models  # noqa: F401 — side-effect import registers all ORM mappers

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # Seed default policies only on a fresh database
        from models.alert import Policy  # local import avoids circularity at module-top
        from models.agent import Agent

        if db.query(func.count(Agent.id)).scalar() == 0:
            defaults = [
                ("realtime", "true", "Continuous file scanning and behavior monitoring"),
                ("firewall", "true", "Automated firewall rule management"),
                ("usbControl", "true", "Block unauthorized USB storage devices"),
                ("webFilter", "false", "Block malicious and phishing URLs"),
                ("appControl", "true", "Whitelist-based application execution policy"),
                ("scriptControl", "false", "Monitor and restrict script execution"),
                ("ransomware", "true", "Advanced ransomware behavior detection"),
                ("networkIntel", "true", "Real-time network threat intelligence feed"),
            ]
            for key, value, desc in defaults:
                db.add(Policy(key=key, value=value, description=desc, updated_at=datetime.utcnow()))
            db.commit()
    except Exception as e:
        logger.error("Default policy seeding failed — defaults were not created", error=str(e))
        db.rollback()
    finally:
        db.close()

    yield
