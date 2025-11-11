"""
Main security testing orchestrator for Firebase.
"""

from typing import List, Optional, Dict, Any
from firebomb.client import FirebaseClient
from firebomb.models import SecurityFinding, FirebaseConfig, EnumerationResult
from firebomb.enumeration import FirebaseEnumerator
from firebomb.firestore_tester import FirestoreTester
from firebomb.rtdb_tester import RTDBTester
from firebomb.storage_tester import StorageTester
from firebomb.functions_tester import FunctionsTester
from firebomb.auth_tester import AuthTester


class FirebaseTester:
    """
    Main security testing orchestrator.
    Coordinates enumeration and testing across all Firebase services.
    """

    def __init__(self, config: FirebaseConfig, auth_token: Optional[str] = None):
        """
        Initialize Firebase tester.

        Args:
            config: FirebaseConfig with project details
            auth_token: Optional authentication token for authenticated testing
        """
        self.config = config
        self.auth_token = auth_token

        # Initialize client
        config_dict = {
            "project_id": config.project_id,
            "api_key": config.api_key,
            "auth_domain": config.auth_domain,
            "database_url": config.database_url,
            "storage_bucket": config.storage_bucket,
        }
        self.client = FirebaseClient(config_dict, auth_token)

        # Initialize enumerator
        self.enumerator = FirebaseEnumerator(self.client)

        # Initialize testers
        self.firestore_tester = FirestoreTester(self.client)
        self.rtdb_tester = RTDBTester(self.client)
        self.storage_tester = StorageTester(self.client)
        self.functions_tester = FunctionsTester(self.client)
        self.auth_tester = AuthTester(self.client)

    def enumerate(self) -> EnumerationResult:
        """
        Enumerate all Firebase resources.

        Returns:
            EnumerationResult with discovered resources
        """
        return self.enumerator.enumerate_all()

    def test_all(self, enumeration_result: Optional[EnumerationResult] = None) -> List[SecurityFinding]:
        """
        Run all security tests.

        Args:
            enumeration_result: Optional pre-enumerated resources. If None, will enumerate first.

        Returns:
            List of SecurityFinding objects
        """
        # Enumerate if not provided
        if enumeration_result is None:
            enumeration_result = self.enumerate()

        findings = []

        # Test Firestore
        if enumeration_result.firestore_collections:
            findings.extend(self.firestore_tester.test(enumeration_result.firestore_collections))

        # Test Realtime Database
        if enumeration_result.rtdb_paths:
            findings.extend(self.rtdb_tester.test(enumeration_result.rtdb_paths))

        # Test Cloud Storage
        if enumeration_result.storage_buckets:
            findings.extend(self.storage_tester.test(enumeration_result.storage_buckets))

        # Test Cloud Functions
        if enumeration_result.cloud_functions:
            findings.extend(self.functions_tester.test(enumeration_result.cloud_functions))

        # Test Authentication
        if enumeration_result.auth_config:
            findings.extend(self.auth_tester.test(enumeration_result.auth_config))

        # Sort findings by severity
        findings.sort(key=lambda f: self._severity_weight(f.severity), reverse=True)

        return findings

    def test_firestore_only(
        self, enumeration_result: Optional[EnumerationResult] = None
    ) -> List[SecurityFinding]:
        """
        Run only Firestore security tests.

        Args:
            enumeration_result: Optional pre-enumerated resources

        Returns:
            List of SecurityFinding objects
        """
        if enumeration_result is None:
            enumeration_result = self.enumerate()

        if not enumeration_result.firestore_collections:
            return []

        return self.firestore_tester.test(enumeration_result.firestore_collections)

    def test_storage_only(
        self, enumeration_result: Optional[EnumerationResult] = None
    ) -> List[SecurityFinding]:
        """
        Run only Cloud Storage security tests.

        Args:
            enumeration_result: Optional pre-enumerated resources

        Returns:
            List of SecurityFinding objects
        """
        if enumeration_result is None:
            enumeration_result = self.enumerate()

        if not enumeration_result.storage_buckets:
            return []

        return self.storage_tester.test(enumeration_result.storage_buckets)

    def test_functions_only(
        self, enumeration_result: Optional[EnumerationResult] = None
    ) -> List[SecurityFinding]:
        """
        Run only Cloud Functions security tests.

        Args:
            enumeration_result: Optional pre-enumerated resources

        Returns:
            List of SecurityFinding objects
        """
        if enumeration_result is None:
            enumeration_result = self.enumerate()

        if not enumeration_result.cloud_functions:
            return []

        return self.functions_tester.test(enumeration_result.cloud_functions)

    def get_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """
        Get a summary of findings.

        Args:
            findings: List of SecurityFinding objects

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
            "info": sum(1 for f in findings if f.severity.value == "info"),
        }

        # Count by resource type
        summary["by_resource_type"] = {}
        for finding in findings:
            if finding.resource_type:
                resource_type = finding.resource_type.value
                summary["by_resource_type"][resource_type] = (
                    summary["by_resource_type"].get(resource_type, 0) + 1
                )

        return summary

    def _severity_weight(self, severity) -> int:
        """
        Get numeric weight for severity sorting.

        Args:
            severity: Severity enum value

        Returns:
            Numeric weight (higher = more severe)
        """
        weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return weights.get(severity.value, 0)
