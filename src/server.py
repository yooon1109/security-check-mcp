from mcp.server.fastmcp import FastMCP

from tools.security_tools import register_security_tools

mcp = FastMCP("security-check")

register_security_tools(mcp)

if __name__ == "__main__":
    mcp.run()
