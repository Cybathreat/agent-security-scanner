"""
Scanning engine for Agent Security Scanner.

Orchestrates security module execution against a target.
Handles module selection, lifecycle management, and result aggregation.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

from typing import List, Optional

from loguru import logger

from .config import Config
from ..modules.base import BaseModule, ScanResult


ALL_MODULES = ["misconfigurations", "prompt_injection", "tool_boundaries", "rag_security"]


class ScanEngine:
    """
    Core scanning engine.

    Instantiates and runs security modules against a target, collecting
    results for downstream reporting.

    Usage:
        engine = ScanEngine(config)
        results = engine.run("https://api.example.com")
    """

    def __init__(self, config: Config) -> None:
        """
        Initialize the scan engine.

        Args:
            config: Loaded scanner configuration.
        """
        self.config = config

    def run(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        timeout: int = 30,
    ) -> List[ScanResult]:
        """
        Execute a security scan against the target.

        Args:
            target: URL or API endpoint to scan.
            modules: List of module names to run. Defaults to all modules.
            timeout: Per-request timeout in seconds.

        Returns:
            List[ScanResult]: Results from each executed module.
        """
        module_names = modules if modules is not None else ALL_MODULES

        logger.info(f"Scan started — target: {target}")
        logger.info(f"Modules: {', '.join(module_names)}")
        logger.info(f"Timeout: {timeout}s")

        results: List[ScanResult] = []

        for name in module_names:
            module = self._build_module(name)
            if module is None:
                continue

            logger.info(f"Running module: {name}")
            result = module.scan(target, timeout=timeout)
            results.append(result)

            logger.info(
                f"Module {name} complete: "
                f"{len(result.findings)} findings, "
                f"{len(result.errors)} errors"
            )

        logger.info(
            f"Scan complete — "
            f"{len(results)} modules, "
            f"{sum(len(r.findings) for r in results)} total findings"
        )

        return results

    def _build_module(self, name: str) -> Optional[BaseModule]:
        """
        Instantiate a module with its configuration.

        Imports are deferred to avoid circular import between core and modules.

        Args:
            name: Module name.

        Returns:
            BaseModule instance, or None if the name is unknown.
        """
        # Deferred imports to break the core <-> modules circular dependency
        from ..modules.misconfigurations import MisconfigurationsModule
        from ..modules.prompt_injection import PromptInjectionModule
        from ..modules.rag_security import RAGSecurityModule
        from ..modules.tool_boundaries import ToolBoundariesModule

        registry = {
            "misconfigurations": (MisconfigurationsModule, self.config.modules.misconfigurations),
            "prompt_injection": (PromptInjectionModule, self.config.modules.prompt_injection),
            "tool_boundaries": (ToolBoundariesModule, self.config.modules.tool_boundaries),
            "rag_security": (RAGSecurityModule, self.config.modules.rag_security),
        }

        if name not in registry:
            logger.warning(f"Unknown module '{name}', skipping")
            return None

        module_class, module_config = registry[name]
        return module_class(module_config)
