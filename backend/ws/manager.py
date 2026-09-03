"""WebSocket connection manager and global singleton instances."""
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)  # client disconnected — stop tracking it instead of leaking it forever
        for connection in dead:
            self.active_connections.remove(connection)


# Global singletons used by route handlers and WebSocket routes
ws_alerts = ConnectionManager()
ws_agents = ConnectionManager()
ws_monitoring: dict[str, ConnectionManager] = {}
