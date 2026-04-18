from mcp.server.fastmcp import FastMCP

try:
    from . import config  # noqa: F401  — loguru 설정 및 dotenv 로딩
    from .tools.security_tools import register_security_tools
except ImportError:
    import config  # type: ignore[no-redef]  # noqa: F401
    from tools.security_tools import register_security_tools

mcp = FastMCP("security-check")

register_security_tools(mcp)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
