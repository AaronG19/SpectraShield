import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler


class AgentLogger:
    def __init__(self, name: str = "agent", log_dir: str = "logs", level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self.logger.propagate = False
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "agent.log")
        fh = RotatingFileHandler(log_file, maxBytes=5_242_880, backupCount=3)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        ))
        self.logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        ))
        self.logger.addHandler(sh)
        self._log_dir = log_dir

    def _extra(self, **kwargs):
        if kwargs:
            return " | " + " ".join(f"{k}={v}" for k, v in kwargs.items())
        return ""

    def info(self, msg, **kw):
        self.logger.info("%s%s", msg, self._extra(**kw))

    def warn(self, msg, **kw):
        self.logger.warning("%s%s", msg, self._extra(**kw))

    def error(self, msg, **kw):
        self.logger.error("%s%s", msg, self._extra(**kw))

    def debug(self, msg, **kw):
        self.logger.debug("%s%s", msg, self._extra(**kw))


log = AgentLogger()
