import os
from dotenv import load_dotenv

load_dotenv()

from loguru import logger

SERVER_NAME: str = os.getenv("MCP_SERVER_NAME", "security-check-mcp")

# Loguru 로그 설정
logger.add("logs/{time}.log", rotation="1 day", retention="7 days", level="INFO")
