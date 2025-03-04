import logging
import os
from logging.handlers import RotatingFileHandler

LOG_FILE = "ccm-agent.log"

class CustomAdapter(logging.LoggerAdapter):
    """Custom LoggerAdapter that injects a custom_id into log messages."""
    
    def process(self, msg, kwargs):
        return f"[ID: {self.extra['custom_id']}] {msg}", kwargs

def get_logger(name, custom_id):
    """Returns a logger with a CustomAdapter for consistent logging."""
    logger = logging.getLogger(name)
    # handler = logging.StreamHandler()  # Logs to console
    max_bytes = 50 * 1024 # 50KB to test the rotation
    backup_count = 30 # up to 30 old log files
    # file_handler = RotatingFileHandler('ccm-agent.log', max_bytes, backup_count)

    file_handler = RotatingFileHandler(LOG_FILE)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    # Create a stream handler (logs to console)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(file_formatter)
    
    if not logger.handlers:  # Prevent duplicate handlers
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
        logger.setLevel(logging.DEBUG)

    return CustomAdapter(logger, {"custom_id": custom_id})
