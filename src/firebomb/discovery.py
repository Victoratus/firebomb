"""
Firebase configuration discovery from web applications.
"""

import requests
from bs4 import BeautifulSoup
from typing import Optional, List
import re
import json
from urllib.parse import urljoin, urlparse
from pathlib import Path

from firebomb.models import FirebaseConfig
from firebomb.utils import (
    extract_firebase_config_from_js,
    normalize_firebase_config,
    is_valid_firebase_project_id,
    is_valid_firebase_api_key,
)


class FirebaseDiscovery:
    """Discovers Firebase configurations from web applications."""

    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None):
        """
        Initialize discovery engine.

        Args:
            timeout: HTTP request timeout in seconds
            user_agent: Custom user agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )

    def discover_from_url(self, url: str, deep_crawl: bool = False) -> Optional[FirebaseConfig]:
        """
        Discover Firebase configuration from a URL.

        Args:
            url: Target URL
            deep_crawl: Whether to crawl linked JavaScript files

        Returns:
            FirebaseConfig if found, None otherwise
        """
        try:
            # Fetch the main page
            headers = {"User-Agent": self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()

            # Try to extract from inline scripts
            config = self._extract_from_html(response.text)
            if config:
                config.source_url = url
                return config

            # Try to extract from linked JavaScript files
            if deep_crawl:
                js_urls = self._extract_js_urls(response.text, url)
                for js_url in js_urls:
                    config = self.discover_from_js_url(js_url)
                    if config:
                        config.source_url = js_url
                        return config

            return None
        except Exception as e:
            print(f"Error discovering from URL {url}: {e}")
            return None

    def discover_from_js_file(self, file_path: str) -> Optional[FirebaseConfig]:
        """
        Discover Firebase configuration from a JavaScript file.

        Args:
            file_path: Path to JavaScript file

        Returns:
            FirebaseConfig if found, None otherwise
        """
        try:
            path = Path(file_path)
            if not path.exists():
                print(f"File not found: {file_path}")
                return None

            js_content = path.read_text(encoding="utf-8")
            return self._extract_from_js(js_content, str(path))
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

    def discover_from_js_url(self, js_url: str) -> Optional[FirebaseConfig]:
        """
        Discover Firebase configuration from a JavaScript URL.

        Args:
            js_url: URL to JavaScript file

        Returns:
            FirebaseConfig if found, None otherwise
        """
        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.get(js_url, headers=headers, timeout=self.timeout)
            response.raise_for_status()

            return self._extract_from_js(response.text, js_url)
        except Exception as e:
            print(f"Error fetching JavaScript from {js_url}: {e}")
            return None

    def discover_from_har(self, har_path: str) -> Optional[FirebaseConfig]:
        """
        Discover Firebase configuration from a HAR file.

        Args:
            har_path: Path to HAR file

        Returns:
            FirebaseConfig if found, None otherwise
        """
        try:
            path = Path(har_path)
            if not path.exists():
                print(f"HAR file not found: {har_path}")
                return None

            with open(path, "r", encoding="utf-8") as f:
                har_data = json.load(f)

            # Extract all JavaScript content from HAR
            entries = har_data.get("log", {}).get("entries", [])
            for entry in entries:
                response = entry.get("response", {})
                content = response.get("content", {})
                mime_type = content.get("mimeType", "")

                # Check if it's JavaScript
                if "javascript" in mime_type.lower() or "application/json" in mime_type.lower():
                    text = content.get("text", "")
                    if text:
                        config = self._extract_from_js(text, entry.get("request", {}).get("url", ""))
                        if config:
                            return config

            return None
        except Exception as e:
            print(f"Error parsing HAR file {har_path}: {e}")
            return None

    def _extract_from_html(self, html_content: str) -> Optional[FirebaseConfig]:
        """
        Extract Firebase config from HTML content.

        Args:
            html_content: HTML source code

        Returns:
            FirebaseConfig if found, None otherwise
        """
        soup = BeautifulSoup(html_content, "lxml")

        # Check inline scripts
        for script in soup.find_all("script"):
            if script.string:
                config = self._extract_from_js(script.string, "inline")
                if config:
                    return config

        return None

    def _extract_from_js(self, js_content: str, source: str) -> Optional[FirebaseConfig]:
        """
        Extract Firebase config from JavaScript content.

        Args:
            js_content: JavaScript source code
            source: Source identifier (URL or file path)

        Returns:
            FirebaseConfig if found, None otherwise
        """
        raw_config = extract_firebase_config_from_js(js_content)
        if not raw_config:
            return None

        # Normalize the configuration
        normalized = normalize_firebase_config(raw_config)

        # Validate required fields
        project_id = normalized.get("project_id")
        api_key = normalized.get("api_key")

        if not project_id or not api_key:
            return None

        if not is_valid_firebase_project_id(project_id):
            print(f"Warning: Invalid project ID format: {project_id}")

        if not is_valid_firebase_api_key(api_key):
            print(f"Warning: Invalid API key format: {api_key}")

        # Create FirebaseConfig object
        config = FirebaseConfig(
            project_id=project_id,
            api_key=api_key,
            auth_domain=normalized.get("auth_domain"),
            database_url=normalized.get("database_url"),
            storage_bucket=normalized.get("storage_bucket"),
            messaging_sender_id=normalized.get("messaging_sender_id"),
            app_id=normalized.get("app_id"),
            measurement_id=normalized.get("measurement_id"),
            source_url=source,
        )

        return config

    def _extract_js_urls(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract JavaScript URLs from HTML.

        Args:
            html_content: HTML source code
            base_url: Base URL for resolving relative URLs

        Returns:
            List of JavaScript URLs
        """
        soup = BeautifulSoup(html_content, "lxml")
        js_urls = []

        for script in soup.find_all("script", src=True):
            src = script["src"]
            # Resolve relative URLs
            full_url = urljoin(base_url, src)
            # Only include JavaScript files
            if full_url.endswith(".js") or "javascript" in full_url.lower():
                js_urls.append(full_url)

        return js_urls

    def validate_config(self, config: FirebaseConfig) -> bool:
        """
        Validate a Firebase configuration by testing connectivity.

        Args:
            config: FirebaseConfig to validate

        Returns:
            True if valid and accessible, False otherwise
        """
        try:
            # Try to access Firestore API
            url = (
                f"https://firestore.googleapis.com/v1/projects/{config.project_id}/"
                f"databases/(default)/documents"
            )
            params = {"key": config.api_key}
            response = requests.get(url, params=params, timeout=5)

            # Any response (even 403) means the project exists and API key is valid
            return response.status_code in [200, 403]
        except Exception:
            return False
