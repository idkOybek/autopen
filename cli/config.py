"""CLI configuration management."""

import os
from pathlib import Path
from typing import Any, Dict

import yaml


CONFIG_FILE = Path.home() / ".pentest-cli.yaml"
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000/api",
    "timeout": 30,
    "verify_ssl": True,
    "output_dir": str(Path.home() / "pentest-reports"),
}


def load_config() -> Dict[str, Any]:
    """Load configuration from file or return defaults.

    Returns:
        Dict containing configuration settings.
    """
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = yaml.safe_load(f) or {}
                # Merge with defaults
                return {**DEFAULT_CONFIG, **config}
        except Exception:
            # If config file is corrupt, return defaults
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> None:
    """Save configuration to file.

    Args:
        config: Dictionary containing configuration settings.
    """
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(CONFIG_FILE, "w") as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)


def get_api_base() -> str:
    """Get API base URL from config or environment.

    Priority:
        1. PENTEST_API_URL environment variable
        2. Config file setting
        3. Default value

    Returns:
        API base URL string.
    """
    # Check environment variable first
    env_url = os.getenv("PENTEST_API_URL")
    if env_url:
        return env_url

    # Load from config file
    config = load_config()
    return config.get("api_url", DEFAULT_CONFIG["api_url"])


def get_timeout() -> int:
    """Get request timeout from config.

    Returns:
        Timeout in seconds.
    """
    config = load_config()
    return config.get("timeout", DEFAULT_CONFIG["timeout"])


def get_output_dir() -> Path:
    """Get default output directory for reports.

    Returns:
        Path object for output directory.
    """
    config = load_config()
    output_dir = config.get("output_dir", DEFAULT_CONFIG["output_dir"])
    return Path(output_dir)


def verify_ssl_enabled() -> bool:
    """Check if SSL verification is enabled.

    Returns:
        True if SSL verification should be performed.
    """
    config = load_config()
    return config.get("verify_ssl", DEFAULT_CONFIG["verify_ssl"])
