"""Check that the installed package can expose its initial release version."""

from agent_risk import __version__


def test_installed_package_version() -> None:
    """Exercise the src-layout installation and distribution metadata."""
    assert __version__ == "0.1.0"
