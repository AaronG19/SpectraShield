"""WebSocket routes."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ws.manager import ConnectionManager, ws_alerts, ws_agents, ws_monitoring

router = APIRouter(tags=["websockets"])


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_alerts.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_alerts.disconnect(websocket)


@router.websocket("/ws/agents")
async def websocket_agents(websocket: WebSocket):
    await ws_agents.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_agents.disconnect(websocket)


@router.websocket("/ws/monitoring/{agent_id}")
async def websocket_monitoring(websocket: WebSocket, agent_id: str):
    if agent_id not in ws_monitoring:
        ws_monitoring[agent_id] = ConnectionManager()
    await ws_monitoring[agent_id].connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_monitoring[agent_id].disconnect(websocket)
