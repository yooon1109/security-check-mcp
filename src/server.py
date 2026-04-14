from mcp.server.fastmcp import FastMCP

import config  # noqa: F401  — loguru 설정 및 dotenv 로딩
from tools.security_tools import register_security_tools

mcp = FastMCP("security-check")

register_security_tools(mcp)

if __name__ == "__main__":
    mcp.run()
