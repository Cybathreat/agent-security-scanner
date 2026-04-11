"""
Structured logging module for Agent Security Scanner.

Uses loguru for structured, rotating log files with JSON serialization option.
All log messages include context: module, function, timestamp, severity.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

from loguru import logger


def setup_logger(
    log_dir: Optional[str] = None,
    level: str = "INFO",
    serialize: bool = False,
    rotation: str = "10 MB",
    retention: str = "7 days",
    compression: str = "zip",
) -> None:
    """
    Configure structured logging for the scanner.

    Sets up:
    - Console output with colored formatting
    - Rotating file output with compression
    - Optional JSON serialization for log aggregation

    Args:
        log_dir: Directory for log files. Default: ./logs
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        serialize: If True, output JSON-formatted logs
        rotation: Max size before rotation (e.g., "10 MB", "1 GB")
        retention: How long to keep old logs (e.g., "7 days", "1 month")
        compression: Compression format for rotated logs (zip, gz, bz2)

    Example:
        >>> setup_logger(log_dir="logs", level="DEBUG")
        >>> logger.info("Scanner started")
        >>> logger.error("Scan failed", exc_info=True)
    """
    # Remove default handler
    logger.remove()

    # Determine log directory
    if log_dir is None:
        log_dir = "logs"

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Console format - human readable with colors
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    # File format - more detailed for debugging
    file_format = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
        "{name}:{function}:{line} | {process.id} | {thread.id} | {message}"
    )

    # Add console handler
    logger.add(
        sys.stderr,
        format=console_format,
        level=level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # Add file handler - plain text
    logger.add(
        log_path / "scanner.log",
        format=file_format,
        level=level,
        rotation=rotation,
        retention=retention,
        compression=compression,
        backtrace=True,
        diagnose=True,
        enqueue=True,  # Thread-safe
    )

    # Add JSON handler if serialization enabled
    if serialize:
        logger.add(
            log_path / "scanner.json",
            format="{message}",
            level=level,
            rotation=rotation,
            retention=retention,
            compression=compression,
            serialize=True,
            enqueue=True,
        )

    logger.debug(f"Logger initialized: level={level}, log_dir={log_path}")


def get_logger(name: Optional[str] = None) -> Any:
    """
    Get a logger instance with optional custom name.

    Args:
        name: Optional logger name for categorization.

    Returns:
        logger: Configured loguru logger instance.

    Example:
        >>> log = get_logger("prompt_injection")
        >>> log.info("Testing payload")
    """
    if name:
        return logger.bind(name=name)
    return logger


# Module-level convenience functions
def debug(message: str, **kwargs) -> None:
    """Log debug message."""
    logger.debug(message, **kwargs)


def info(message: str, **kwargs) -> None:
    """Log info message."""
    logger.info(message, **kwargs)


def warning(message: str, **kwargs) -> None:
    """Log warning message."""
    logger.warning(message, **kwargs)


def error(message: str, **kwargs) -> None:
    """Log error message."""
    logger.error(message, **kwargs)


def critical(message: str, **kwargs) -> None:
    """Log critical message."""
    logger.critical(message, **kwargs)


def exception(message: str, **kwargs) -> None:
    """Log exception with traceback."""
    logger.exception(message, **kwargs)
