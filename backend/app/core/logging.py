"""Request logs. Passwords, cookies, and authorization headers are not recorded."""

import logging
import re

_SECRET = re.compile(r"(password|cookie|authorization|bearer\s)", re.IGNORECASE)
_CONFIGURED = False


class SecretFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if _SECRET.search(record.getMessage()):
            record.msg = "redacted log line"
            record.args = ()
        return True


def configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    handler.addFilter(SecretFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    _CONFIGURED = True
