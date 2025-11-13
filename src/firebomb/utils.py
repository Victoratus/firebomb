"""
Utility functions for Firebomb.
"""

import json
import re
from typing import Optional, Dict, Any
from pathlib import Path


def extract_firebase_config_from_js(js_content: str) -> Optional[Dict[str, str]]:
    """
    Extract Firebase configuration from JavaScript content.

    Args:
        js_content: JavaScript source code

    Returns:
        Dictionary with Firebase config keys or None if not found
    """
    config = {}

    # Pattern 1: firebaseConfig object
    firebase_config_pattern = r'firebaseConfig\s*=\s*({[^}]+})'
    match = re.search(firebase_config_pattern, js_content, re.DOTALL)
    if match:
        try:
            # Extract the object and try to parse it as JSON
            obj_str = match.group(1)
            # Clean up JavaScript object syntax to make it JSON-compatible
            obj_str = re.sub(r'(\w+):', r'"\1":', obj_str)  # Add quotes to keys
            obj_str = re.sub(r"'", '"', obj_str)  # Replace single quotes
            config_obj = json.loads(obj_str)
            config.update(config_obj)
        except json.JSONDecodeError:
            pass

    # Pattern 2: Individual firebase properties
    patterns = {
        'apiKey': r'apiKey\s*[:=]\s*["\']([^"\']+)["\']',
        'authDomain': r'authDomain\s*[:=]\s*["\']([^"\']+)["\']',
        'databaseURL': r'databaseURL\s*[:=]\s*["\']([^"\']+)["\']',
        'projectId': r'projectId\s*[:=]\s*["\']([^"\']+)["\']',
        'storageBucket': r'storageBucket\s*[:=]\s*["\']([^"\']+)["\']',
        'messagingSenderId': r'messagingSenderId\s*[:=]\s*["\']([^"\']+)["\']',
        'appId': r'appId\s*[:=]\s*["\']([^"\']+)["\']',
        'measurementId': r'measurementId\s*[:=]\s*["\']([^"\']+)["\']',
    }

    for key, pattern in patterns.items():
        if key not in config:
            match = re.search(pattern, js_content, re.IGNORECASE)
            if match:
                config[key] = match.group(1)

    # Pattern 3: initializeApp call
    init_pattern = r'initializeApp\s*\(\s*({[^}]+})\s*\)'
    match = re.search(init_pattern, js_content, re.DOTALL)
    if match and not config:
        try:
            obj_str = match.group(1)
            obj_str = re.sub(r'(\w+):', r'"\1":', obj_str)
            obj_str = re.sub(r"'", '"', obj_str)
            config_obj = json.loads(obj_str)
            config.update(config_obj)
        except json.JSONDecodeError:
            pass

    return config if config else None


def normalize_firebase_config(config: Dict[str, Any]) -> Dict[str, str]:
    """
    Normalize Firebase configuration keys to standard format.

    Args:
        config: Raw configuration dictionary

    Returns:
        Normalized configuration dictionary
    """
    key_mapping = {
        'apiKey': 'api_key',
        'authDomain': 'auth_domain',
        'databaseURL': 'database_url',
        'projectId': 'project_id',
        'storageBucket': 'storage_bucket',
        'messagingSenderId': 'messaging_sender_id',
        'appId': 'app_id',
        'measurementId': 'measurement_id',
    }

    normalized = {}
    for key, value in config.items():
        normalized_key = key_mapping.get(key, key)
        normalized[normalized_key] = value

    return normalized


def is_valid_firebase_project_id(project_id: str) -> bool:
    """
    Validate Firebase project ID format.

    Args:
        project_id: Project ID to validate

    Returns:
        True if valid, False otherwise
    """
    if not project_id:
        return False
    # Firebase project IDs are typically lowercase with hyphens
    pattern = r'^[a-z][a-z0-9-]*[a-z0-9]$'
    return bool(re.match(pattern, project_id)) and len(project_id) >= 6


def is_valid_firebase_api_key(api_key: str) -> bool:
    """
    Validate Firebase API key format.

    Args:
        api_key: API key to validate

    Returns:
        True if valid, False otherwise
    """
    if not api_key:
        return False
    # Firebase API keys typically start with "AIza" and are 39 characters long
    return api_key.startswith("AIza") and len(api_key) == 39


def get_cache_path() -> Path:
    """
    Get the path to the Firebomb cache file.

    Returns:
        Path to cache file
    """
    return Path.home() / ".firebomb.json"


def load_cache() -> Dict[str, Any]:
    """
    Load cached Firebase configurations.

    Returns:
        Dictionary of cached configurations
    """
    cache_path = get_cache_path()
    if not cache_path.exists():
        return {}

    try:
        with open(cache_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_cache(cache: Dict[str, Any]) -> None:
    """
    Save Firebase configurations to cache.

    Args:
        cache: Dictionary of configurations to cache
    """
    cache_path = get_cache_path()
    try:
        with open(cache_path, "w") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save cache: {e}")


def sanitize_path(path: str) -> str:
    """
    Sanitize a database path for safe usage.

    Args:
        path: Path to sanitize

    Returns:
        Sanitized path
    """
    # Remove leading/trailing slashes and whitespace
    path = path.strip().strip("/")
    # Remove any dangerous characters
    path = re.sub(r'[^\w\-/.]', '', path)
    return path


def format_bytes(size: int) -> str:
    """
    Format bytes into human-readable format.

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def truncate_string(s: str, max_length: int = 100) -> str:
    """
    Truncate a string to a maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length

    Returns:
        Truncated string with ellipsis if needed
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."
