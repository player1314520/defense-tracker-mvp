"""Default logging redaction for credentials and authorization material."""
from __future__ import annotations

import logging
import re


_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{8,})"),
    re.compile(
        r"""(?ix)
        (api[_-]?key|app[_-]?secret|access[_-]?token|verify[_-]?token|
         recovery[_-]?code|pairing[_-]?code)
        (\s*["']?\s*[:=]\s*["']?)
        ([^\s"',;}]{4,})
        """
    ),
)


def redact_text(value: str) -> str:
    text = str(value)
    text = _PATTERNS[0].sub("Bearer [REDACTED]", text)
    text = _PATTERNS[1].sub("[REDACTED]", text)
    text = _PATTERNS[2].sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        text,
    )
    return text


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        return True


def install_redaction_filter(logger: logging.Logger) -> SecretRedactionFilter:
    redactor = SecretRedactionFilter()
    logger.addFilter(redactor)
    for handler in logging.getLogger().handlers:
        handler.addFilter(redactor)
    return redactor
