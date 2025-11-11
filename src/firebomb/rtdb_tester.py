"""
Realtime Database security rules testing.
"""

from typing import List
from firebomb.client import FirebaseClient
from firebomb.models import SecurityFinding, Severity, ResourceType, RTDBPath


class RTDBTester:
    """Tests Realtime Database security rules."""

    def __init__(self, client: FirebaseClient):
        """
        Initialize RTDB tester.

        Args:
            client: FirebaseClient instance
        """
        self.client = client

    def test(self, paths: List[RTDBPath]) -> List[SecurityFinding]:
        """
        Run all Realtime Database security tests.

        Args:
            paths: List of RTDBPath objects to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        for path in paths:
            findings.extend(self._test_public_read(path))
            findings.extend(self._test_public_write(path))
            findings.extend(self._test_data_exposure(path))

        return findings

    def _test_public_read(self, path: RTDBPath) -> List[SecurityFinding]:
        """
        Test for publicly readable paths.

        Args:
            path: RTDBPath to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if path.readable and path.data_sample is not None:
            severity = Severity.CRITICAL if path.path == "/" else Severity.HIGH

            finding = SecurityFinding(
                severity=severity,
                title=f'Realtime Database Path "{path.path}" Publicly Readable',
                description=(
                    f"The Realtime Database path '{path.path}' allows anonymous read access. "
                    "Anyone with the Firebase API key can read this data without authentication."
                    + (
                        " This path is the root of the database, exposing ALL data."
                        if path.path == "/"
                        else ""
                    )
                ),
                affected_resource=f"Realtime Database Path: {path.path}",
                recommendation=(
                    "Add security rules to restrict read access:\n"
                    "{\n"
                    '  "rules": {\n'
                    f'    "{path.path.strip("/")}": {{\n'
                    '      ".read": "auth != null",\n'
                    '      ".write": "auth != null"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                evidence={
                    "path": path.path,
                    "readable": True,
                    "data_sample": self._truncate_data(path.data_sample),
                },
                cwe="CWE-284: Improper Access Control",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.RTDB,
            )
            findings.append(finding)

        return findings

    def _test_public_write(self, path: RTDBPath) -> List[SecurityFinding]:
        """
        Test for publicly writable paths.

        Args:
            path: RTDBPath to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if path.writable:
            finding = SecurityFinding(
                severity=Severity.CRITICAL,
                title=f'Realtime Database Path "{path.path}" Publicly Writable',
                description=(
                    f"The Realtime Database path '{path.path}' allows anonymous write access. "
                    "Anyone with the Firebase API key can modify or delete this data without authentication. "
                    "This is a critical security vulnerability that could lead to data tampering or loss."
                ),
                affected_resource=f"Realtime Database Path: {path.path}",
                recommendation=(
                    "Add security rules to restrict write access:\n"
                    "{\n"
                    '  "rules": {\n'
                    f'    "{path.path.strip("/")}": {{\n'
                    '      ".write": "auth != null && auth.uid == $uid"\n'
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                evidence={"path": path.path, "writable": True},
                cwe="CWE-284: Improper Access Control",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.RTDB,
            )
            findings.append(finding)

        return findings

    def _test_data_exposure(self, path: RTDBPath) -> List[SecurityFinding]:
        """
        Test for sensitive data exposure in accessible paths.

        Args:
            path: RTDBPath to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if not path.readable or path.data_sample is None:
            return findings

        # Check for sensitive keys in the data
        sensitive_keys = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apiKey",
            "apikey",
            "private_key",
            "privateKey",
            "ssn",
            "credit_card",
            "creditCard",
            "cvv",
            "pin",
            "salt",
            "hash",
            "session",
            "jwt",
        }

        exposed_keys = self._find_sensitive_keys(path.data_sample, sensitive_keys)

        if exposed_keys:
            finding = SecurityFinding(
                severity=Severity.HIGH,
                title=f'Sensitive Data Exposed at Path "{path.path}"',
                description=(
                    f"The publicly readable path '{path.path}' contains data with potentially "
                    f"sensitive keys: {', '.join(exposed_keys)}. This data should not be "
                    "accessible to anonymous users."
                ),
                affected_resource=f"Realtime Database Path: {path.path}",
                recommendation=(
                    "1. Move sensitive data to a protected path\n"
                    "2. Add security rules to restrict access:\n"
                    "{\n"
                    '  "rules": {\n'
                    f'    "{path.path.strip("/")}": {{\n'
                    '      ".read": "auth != null && auth.uid == $uid"\n'
                    "    }\n"
                    "  }\n"
                    "}\n"
                    "3. Consider encrypting sensitive data before storing"
                ),
                evidence={
                    "path": path.path,
                    "sensitive_keys": list(exposed_keys),
                    "data_sample": self._truncate_data(path.data_sample),
                },
                cwe="CWE-359: Exposure of Private Information",
                owasp="API3:2023 Broken Object Property Level Authorization",
                resource_type=ResourceType.RTDB,
            )
            findings.append(finding)

        return findings

    def _find_sensitive_keys(self, data: any, sensitive_keys: set, max_depth: int = 5) -> set:
        """
        Recursively find sensitive keys in data structure.

        Args:
            data: Data to search
            sensitive_keys: Set of sensitive key names
            max_depth: Maximum recursion depth

        Returns:
            Set of found sensitive keys
        """
        if max_depth <= 0:
            return set()

        found_keys = set()

        if isinstance(data, dict):
            for key, value in data.items():
                # Check if key is sensitive
                if key.lower() in sensitive_keys or any(sk in key.lower() for sk in sensitive_keys):
                    found_keys.add(key)

                # Recurse into nested structures
                found_keys.update(self._find_sensitive_keys(value, sensitive_keys, max_depth - 1))
        elif isinstance(data, list):
            for item in data:
                found_keys.update(self._find_sensitive_keys(item, sensitive_keys, max_depth - 1))

        return found_keys

    def _truncate_data(self, data: any, max_size: int = 200) -> any:
        """
        Truncate data for evidence reporting.

        Args:
            data: Data to truncate
            max_size: Maximum size in characters

        Returns:
            Truncated data
        """
        import json

        try:
            data_str = json.dumps(data)
            if len(data_str) > max_size:
                return data_str[:max_size] + "..."
            return data
        except Exception:
            return str(data)[:max_size]
