"""Self-contained factory image tools.

This package is intentionally additive. The current production scripts remain
available while the codex_v1 entry point is evaluated.
"""

from .config import FactoryConfig, load_factory_config
from .workflow import run_factory_flow

__all__ = ("FactoryConfig", "load_factory_config", "run_factory_flow")
