import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


class AgentLogger:
    _instances = {}

    def __new__(cls, name: str = "agent_security"):
        if name not in cls._instances:
            instance = super().__new__(cls)
            instance.logger = logging.getLogger(name)
            instance.logger.setLevel(logging.INFO)
            instance.logger.propagate = False
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(StructuredFormatter())
            instance.logger.handlers.clear()
            instance.logger.addHandler(handler)
            cls._instances[name] = instance
        return cls._instances[name]

    @classmethod
    def configure(
        cls,
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        max_bytes: int = 10_485_760,
        backup_count: int = 5,
    ):
        level = getattr(logging, log_level.upper(), logging.INFO)
        for logger in cls._instances.values():
            logger.logger.setLevel(level)
            for h in logger.logger.handlers:
                if isinstance(h, logging.StreamHandler):
                    h.setLevel(level)
            if log_file:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
                fh.setFormatter(StructuredFormatter())
                fh.setLevel(level)
                logger.logger.addHandler(fh)

    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, kwargs)

    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, kwargs)

    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, kwargs)

    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, kwargs)

    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, kwargs)

    def _log(self, level: int, message: str, extra: dict):
        if extra:
            record = self.logger.makeRecord(
                self.logger.name, level, "", 0, message, (), None
            )
            record.extra_fields = extra
            self.logger.handle(record)
        else:
            self.logger.log(level, message)


logger = AgentLogger("agent_security")
