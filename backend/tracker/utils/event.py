import threading


class EventEmitter:
    def __init__(self):
        self._listeners = {}
        self._lock = threading.Lock()

    def on(self, event, callback):
        with self._lock:
            self._listeners.setdefault(event, []).append(callback)

    def off(self, event, callback):
        with self._lock:
            self._listeners.setdefault(event, []).append(callback)
            if callback in self._listeners[event]:
                self._listeners[event].remove(callback)

    def emit(self, event, *args, **kwargs):
        with self._lock:
            callbacks = list(self._listeners.get(event, []))
        for cb in callbacks:
            try:
                cb(*args, **kwargs)
            except Exception:
                pass
