"""Python package scaffold for the agent-risk MLSD project."""

from importlib.metadata import version
from typing import Final

__all__ = ["__version__"]

__version__: Final[str] = version("agent-risk")
