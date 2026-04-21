"""
Config API endpoints.

GET   /api/config   — Get current scanner configuration
PATCH /api/config   — Update scanner configuration
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml
from fastapi import APIRouter

from ...core.config import load_config
from ..models import ConfigResponse

router = APIRouter(prefix="/config", tags=["config"])


@router.get("", response_model=ConfigResponse)
async def get_config() -> ConfigResponse:
    """Get current scanner configuration."""
    config = load_config()
    config_dict = config.to_dict()

    return ConfigResponse(
        scanner=config_dict.get("scanner", {}),
        quality_gate=config_dict.get("quality_gate", {}),
        modules=config_dict.get("modules", {}),
    )


@router.patch("", response_model=ConfigResponse)
async def update_config(updates: Dict[str, Any]) -> ConfigResponse:
    """Update scanner configuration and persist to YAML."""
    config = load_config()

    # Apply scanner updates
    if "scanner" in updates and isinstance(updates["scanner"], dict):
        for key, value in updates["scanner"].items():
            if hasattr(config.scanner, key):
                setattr(config.scanner, key, value)

    # Apply quality_gate updates
    if "quality_gate" in updates and isinstance(updates["quality_gate"], dict):
        for key, value in updates["quality_gate"].items():
            if hasattr(config.quality_gate, key):
                setattr(config.quality_gate, key, value)

    # Apply module-specific updates
    if "modules" in updates and isinstance(updates["modules"], dict):
        for mod_name, mod_updates in updates["modules"].items():
            if hasattr(config.modules, mod_name) and isinstance(mod_updates, dict):
                mod_config = getattr(config.modules, mod_name)
                for key, value in mod_updates.items():
                    if hasattr(mod_config, key):
                        setattr(mod_config, key, value)

    # Persist to YAML
    config_path = os.environ.get("ASS_CONFIG_PATH", "config/config.yaml")
    config_path_resolved = Path(config_path)
    config_path_resolved.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path_resolved, "w") as f:
        yaml.dump(config.to_dict(), f, default_flow_style=False)

    config_dict = config.to_dict()
    return ConfigResponse(
        scanner=config_dict.get("scanner", {}),
        quality_gate=config_dict.get("quality_gate", {}),
        modules=config_dict.get("modules", {}),
    )