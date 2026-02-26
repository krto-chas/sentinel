"""
Strukturerad JSON-loggning för Sentinel.

Använder python-json-logger för att producera maskinläsbara loggar
som fungerar med log aggregation-verktyg som Loki, ELK och Cloud Logging.

Varje loggpost innehåller:
  - timestamp  : ISO 8601 UTC
  - level      : DEBUG / INFO / WARNING / ERROR / CRITICAL
  - logger     : loggerns namn (t.ex. "sentinel", "uvicorn.error")
  - message    : loggmeddelandet
  - service    : "sentinel" (statisk identifierare för filtrering)
  - environment: från env-variabeln ENVIRONMENT (default: "production")
  - + eventuella extra-fält som skickas med logger.info(..., extra={...})
"""

import logging
import logging.config
import os

from pythonjsonlogger.jsonlogger import JsonFormatter  # type: ignore[import-untyped]


class _SentinelJsonFormatter(JsonFormatter):
    """Lägger till statiska fält som service och environment på varje post."""

    _service = "sentinel"
    _environment = os.getenv("ENVIRONMENT", "production")

    def add_fields(
        self,
        log_record: dict,
        record: logging.LogRecord,
        message_dict: dict,
    ) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record["service"] = self._service
        log_record["environment"] = self._environment
        # Byt namn på Pythons standardfält till mer läsbara nycklar
        log_record["level"] = log_record.pop("levelname", record.levelname)
        log_record["logger"] = log_record.pop("name", record.name)


def setup_logging(level: str | None = None) -> None:
    """
    Konfigurera root logger och alla relevanta sub-loggers med JSON-format.

    Anropas en gång vid applikationsstart (i lifespan).
    level: loggningsnivå som sträng, t.ex. "DEBUG", "INFO" (default från
           env-variabeln LOG_LEVEL, annars "INFO").
    """
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()

    fmt = _SentinelJsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        rename_fields={"asctime": "timestamp"},
    )

    handler = logging.StreamHandler()
    handler.setFormatter(fmt)

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "handlers": {
                "json": {
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                    "stream": "ext://sys.stdout",
                },
            },
            "formatters": {
                "json": {
                    "()": _SentinelJsonFormatter,
                    "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
                    "datefmt": "%Y-%m-%dT%H:%M:%S",
                    "rename_fields": {"asctime": "timestamp"},
                },
            },
            "root": {
                "handlers": ["json"],
                "level": log_level,
            },
            # Sätt uvicorn-loggers till samma handler så all output är JSON
            "loggers": {
                "uvicorn": {"handlers": ["json"], "level": log_level, "propagate": False},
                "uvicorn.error": {"handlers": ["json"], "level": log_level, "propagate": False},
                "uvicorn.access": {"handlers": ["json"], "level": log_level, "propagate": False},
                "sentinel": {"handlers": ["json"], "level": log_level, "propagate": False},
                "apscheduler": {"handlers": ["json"], "level": "WARNING", "propagate": False},
            },
        }
    )
