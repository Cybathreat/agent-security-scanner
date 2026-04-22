"""
Agent attacks module for Singularity.

Provides specialized scanners for agentic system vulnerabilities:
- tool_hijacking: Tool argument injection
- recursive_agents: Multi-agent compromise
- memory_poisoning: Persistent memory corruption
- planning_attacks: Chain-of-thought manipulation
"""

from .tool_hijacking import ToolHijackingScanner
from .recursive_agents import RecursiveAgentsScanner
from .memory_poisoning import MemoryPoisoningScanner
from .planning_attacks import PlanningAttacksScanner

__all__ = [
    "ToolHijackingScanner",
    "RecursiveAgentsScanner",
    "MemoryPoisoningScanner",
    "PlanningAttacksScanner",
]