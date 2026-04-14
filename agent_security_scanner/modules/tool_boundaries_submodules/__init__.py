"""
Tool Boundaries module for Agent Security Scanner.

Provides specialized scanners for tool calling boundary validation:
- permission_scanner: Tool permission analysis
- sandbox_scanner: Sandbox configuration audit
- tool_chains: Dangerous tool combinations
- mcp_scanner: MCP server validation
- confused_deputy: Confused deputy attack detection
"""

from .permission_scanner import PermissionScanner
from .sandbox_scanner import SandboxScanner
from .tool_chains import ToolChainsScanner
from .mcp_scanner import MCPScanner
from .confused_deputy import ConfusedDeputyScanner

__all__ = [
    "PermissionScanner",
    "SandboxScanner",
    "ToolChainsScanner",
    "MCPScanner",
    "ConfusedDeputyScanner",
]