"""
Tests for utility functions.
"""

import pytest
from firebomb.utils import (
    extract_firebase_config_from_js,
    normalize_firebase_config,
    is_valid_firebase_project_id,
    is_valid_firebase_api_key,
    sanitize_path,
    format_bytes,
    truncate_string,
)


def test_extract_firebase_config_from_js():
    """Test extracting Firebase config from JavaScript."""
    js_code = """
    const firebaseConfig = {
        apiKey: "AIzaSyTest1234567890123456789012345",
        authDomain: "test-project.firebaseapp.com",
        projectId: "test-project",
        storageBucket: "test-project.appspot.com",
        messagingSenderId: "123456789012",
        appId: "1:123456789012:web:abc123",
    };
    """

    config = extract_firebase_config_from_js(js_code)
    assert config is not None
    assert "apiKey" in config
    assert "projectId" in config


def test_normalize_firebase_config():
    """Test normalizing Firebase config keys."""
    config = {
        "apiKey": "test-key",
        "projectId": "test-project",
        "databaseURL": "https://test.firebaseio.com",
    }

    normalized = normalize_firebase_config(config)
    assert "api_key" in normalized
    assert "project_id" in normalized
    assert "database_url" in normalized


def test_is_valid_firebase_project_id():
    """Test Firebase project ID validation."""
    assert is_valid_firebase_project_id("my-project-123") is True
    assert is_valid_firebase_project_id("test-app") is True
    assert is_valid_firebase_project_id("a") is False
    assert is_valid_firebase_project_id("MyProject") is False
    assert is_valid_firebase_project_id("123-project") is False
    assert is_valid_firebase_project_id("") is False


def test_is_valid_firebase_api_key():
    """Test Firebase API key validation."""
    # Firebase API keys are exactly 39 characters starting with "AIza"
    valid_key = "AIza" + "x" * 35  # Exactly 39 characters
    assert is_valid_firebase_api_key(valid_key) is True
    assert is_valid_firebase_api_key("AIzaSy123") is False
    assert is_valid_firebase_api_key("invalid-key") is False
    assert is_valid_firebase_api_key("") is False


def test_sanitize_path():
    """Test path sanitization."""
    assert sanitize_path("/users/123") == "users/123"
    assert sanitize_path("  /data/  ") == "data"
    # The sanitize_path function removes special characters but doesn't resolve paths
    assert sanitize_path("/test/admin") == "test/admin"


def test_format_bytes():
    """Test byte formatting."""
    assert format_bytes(100) == "100.0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"


def test_truncate_string():
    """Test string truncation."""
    long_string = "a" * 200
    truncated = truncate_string(long_string, max_length=50)
    assert len(truncated) == 50
    assert truncated.endswith("...")

    short_string = "short"
    assert truncate_string(short_string, max_length=50) == "short"
