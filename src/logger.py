import logging
import os
from pathlib import Path

def setup_logger(output_dir: str = "output") -> logging.Logger:
    """
    Sets up a structured logger that writes to both console and a log file.
    
    Args:
        output_dir (str): The folder where log files will be saved.
        
    Returns:
        logging.Logger: The configured logger instance.
    """
    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file_path = log_dir / "phish_detect.log"
    
    logger = logging.getLogger("phish_detect")
    logger.setLevel(logging.DEBUG)
    
    # Avoid duplicate handlers if already initialized
    if logger.handlers:
        return logger
        
    # Formatter for structured logs
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Console Handler (INFO level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File Handler (DEBUG level)
    try:
        file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.error(f"Failed to initialize file logger at {log_file_path}: {e}")
        
    return logger
