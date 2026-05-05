# core/logger.py
# ─────────────────────────────────────────────
# ForensiQ — Centralized Logging
#
# All modules import logger from here.
# Never use print() in production code.
# ─────────────────────────────────────────────

import logging
import logging.handlers
import sys
from pathlib import Path

import config


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger for the given module name.

    Usage in any module:
        from core.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Parsing started")

    Args:
        name: Module name, use __name__ always

    Returns:
        Configured Logger instance
    """
    logger = logging.getLogger(name)

    # Don't add handlers if already configured
    # Prevents duplicate log entries
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    # ── Console Handler ──
    # Shows colored output in terminal
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_format = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_format)

    # ── File Handler ──
    # Rotating file — max 10MB, keeps 5 backups
    # Prevents log files from filling up disk
    file_handler = logging.handlers.RotatingFileHandler(
        filename    = config.LOG_FILE,
        maxBytes    = 10 * 1024 * 1024,  # 10 MB
        backupCount = 5,
        encoding    = "utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
