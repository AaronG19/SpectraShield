"""Report export routes."""
import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert
from authentication.dependencies import get_current_user

router = APIRouter(tags=["reports"])


@router.get("/reports/export")
async def export_report(
    type: str = Query("csv"),
    agent_id: str = Query(None),
    hours: int = Query(24),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Alert)
    if agent_id:
        query = query.filter(Alert.agent_id == agent_id)
    query = query.filter(Alert.created_at >= datetime.utcnow() - timedelta(hours=hours))
    alerts = query.order_by(Alert.created_at.desc()).all()
    if type == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Title", "Severity", "Type", "Status", "AgentID", "Created At"])
        for a in alerts:
            writer.writerow([a.id, a.title, a.severity, a.type, a.status, a.agent_id,
                             a.created_at.isoformat() if a.created_at else ""])
        return Response(content=output.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=alerts_report.csv"})
    return {
        "alerts": [
            {"id": a.id, "title": a.title, "severity": a.severity, "type": a.type,
             "status": a.status, "agent_id": a.agent_id,
             "created_at": a.created_at.isoformat() if a.created_at else ""}
            for a in alerts
        ]
    }
