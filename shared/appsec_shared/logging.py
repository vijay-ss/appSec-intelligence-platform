"""
Structured JSON logging using structlog.
All Python services call configure_logging() at startup.
"""
import logging
import sys
import structlog


def configure_logging(service_name: str, level: str = "INFO") -> structlog.BoundLogger:
    """Configure structlog and return a logger bound with service name."""
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    )
    return structlog.get_logger().bind(service=service_name)
