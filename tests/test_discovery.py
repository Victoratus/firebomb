"""
Tests for Firebase discovery module.
"""

import pytest
from firebomb.discovery import FirebaseDiscovery
from firebomb.models import FirebaseConfig


def test_discovery_initialization():
    """Test FirebaseDiscovery initialization."""
    discovery = FirebaseDiscovery(timeout=5)
    assert discovery.timeout == 5
    assert discovery.user_agent is not None


def test_extract_from_js_with_valid_config():
    """Test extracting config from JavaScript with valid Firebase config."""
    discovery = FirebaseDiscovery()

    js_code = """
    const firebaseConfig = {
        apiKey: "AIzaSyTest1234567890123456789012345",
        authDomain: "test-project.firebaseapp.com",
        projectId: "test-project",
        storageBucket: "test-project.appspot.com",
    };
    firebase.initializeApp(firebaseConfig);
    """

    config = discovery._extract_from_js(js_code, "test.js")
    assert config is not None
    assert config.project_id == "test-project"
    assert config.api_key.startswith("AIza")


def test_extract_from_js_with_no_config():
    """Test extracting config from JavaScript without Firebase config."""
    discovery = FirebaseDiscovery()

    js_code = """
    console.log("Hello World");
    const app = { name: "test" };
    """

    config = discovery._extract_from_js(js_code, "test.js")
    assert config is None


def test_extract_from_js_with_initializeApp():
    """Test extracting config from initializeApp call."""
    discovery = FirebaseDiscovery()

    js_code = """
    firebase.initializeApp({
        apiKey: "AIzaSyTest1234567890123456789012345",
        projectId: "my-firebase-app",
        authDomain: "my-firebase-app.firebaseapp.com"
    });
    """

    config = discovery._extract_from_js(js_code, "app.js")
    assert config is not None
    assert config.project_id == "my-firebase-app"


def test_extract_js_urls():
    """Test extracting JavaScript URLs from HTML."""
    discovery = FirebaseDiscovery()

    html = """
    <html>
        <head>
            <script src="/static/app.js"></script>
            <script src="https://cdn.example.com/firebase.js"></script>
        </head>
        <body>
            <script src="bundle.js"></script>
        </body>
    </html>
    """

    base_url = "https://example.com"
    js_urls = discovery._extract_js_urls(html, base_url)

    assert len(js_urls) >= 2
    assert any("app.js" in url for url in js_urls)
    assert any("bundle.js" in url for url in js_urls)
