"""
Logger Configuration Module
Sets up logging for RedSentinel AI with appropriate formatting and levels.
"""

import logging
import os
from datetime import datetime
from pathlib import Path

def setup_logger(name: str = 'redsentinel', log_level: int = logging.INFO) -> logging.Logger:
    """Set up logger with console and file output"""
    
    # Create logs directory if it doesn't exist
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    log_file = log_dir / f"redsentinel_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

from typing import Optional

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get existing logger or create new one"""
    logger_name = name or 'redsentinel'
    return logging.getLogger(logger_name)
