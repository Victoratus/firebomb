"""
Firestore security rules testing.
"""

from typing import List
from firebomb.client import FirebaseClient
from firebomb.models import SecurityFinding, Severity, ResourceType, FirestoreCollection


class FirestoreTester:
    """Tests Firestore security rules."""

    def __init__(self, client: FirebaseClient):
        """
        Initialize Firestore tester.

        Args:
            client: FirebaseClient instance
        """
        self.client = client

    def test(self, collections: List[FirestoreCollection]) -> List[SecurityFinding]:
        """
        Run all Firestore security tests.

        Args:
            collections: List of FirestoreCollection objects to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        for collection in collections:
            findings.extend(self._test_public_read(collection))
            findings.extend(self._test_public_write(collection))
            findings.extend(self._test_auth_gap(collection))
            findings.extend(self._test_data_exposure(collection))

        return findings

    def _test_public_read(self, collection: FirestoreCollection) -> List[SecurityFinding]:
        """
        Test for publicly readable collections.

        Args:
            collection: FirestoreCollection to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if collection.readable_anon and collection.document_count > 0:
            finding = SecurityFinding(
                severity=Severity.HIGH,
                title=f'Firestore Collection "{collection.name}" Publicly Readable',
                description=(
                    f"The Firestore collection '{collection.name}' allows anonymous read access. "
                    f"Anyone with the Firebase API key can read {collection.document_count} documents "
                    "from this collection without authentication."
                ),
                affected_resource=f"Firestore Collection: {collection.name}",
                recommendation=(
                    "Add security rules to restrict read access to authenticated users only:\n"
                    f"match /databases/{{database}}/documents/{collection.name}/{{document}} {{\n"
                    "  allow read: if request.auth != null;\n"
                    "}"
                ),
                evidence={
                    "collection": collection.name,
                    "document_count": collection.document_count,
                    "readable_anon": True,
                    "sample_documents": collection.sample_documents[:2] if collection.sample_documents else [],
                },
                cwe="CWE-284: Improper Access Control",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.FIRESTORE,
            )
            findings.append(finding)

        return findings

    def _test_public_write(self, collection: FirestoreCollection) -> List[SecurityFinding]:
        """
        Test for publicly writable collections.

        Args:
            collection: FirestoreCollection to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if collection.writable_anon:
            finding = SecurityFinding(
                severity=Severity.CRITICAL,
                title=f'Firestore Collection "{collection.name}" Publicly Writable',
                description=(
                    f"The Firestore collection '{collection.name}' allows anonymous write access. "
                    "Anyone with the Firebase API key can create, modify, or delete documents "
                    "without authentication. This is a critical security vulnerability."
                ),
                affected_resource=f"Firestore Collection: {collection.name}",
                recommendation=(
                    "Add security rules to restrict write access to authenticated users only:\n"
                    f"match /databases/{{database}}/documents/{collection.name}/{{document}} {{\n"
                    "  allow write: if request.auth != null && request.auth.uid == resource.data.userId;\n"
                    "}"
                ),
                evidence={"collection": collection.name, "writable_anon": True},
                cwe="CWE-284: Improper Access Control",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.FIRESTORE,
            )
            findings.append(finding)

        return findings

    def _test_auth_gap(self, collection: FirestoreCollection) -> List[SecurityFinding]:
        """
        Test for authentication gaps (accessible to anon but not auth).

        Args:
            collection: FirestoreCollection to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        # If collection is not readable anonymously but IS readable when authenticated,
        # and has documents, this is expected behavior (not a finding)
        # But if it's NOT readable anonymously and NOT readable when authenticated,
        # and we know the collection exists, it might indicate overly restrictive rules

        # For now, we'll focus on the opposite: if anon can read but auth cannot
        # (which would be unusual and potentially misconfigured)
        if collection.readable_anon and not collection.readable_auth and self.client.auth_token:
            finding = SecurityFinding(
                severity=Severity.MEDIUM,
                title=f'Firestore Collection "{collection.name}" Has Unusual Access Pattern',
                description=(
                    f"The collection '{collection.name}' is readable by anonymous users "
                    "but NOT readable by authenticated users. This is an unusual configuration "
                    "and may indicate misconfigured security rules."
                ),
                affected_resource=f"Firestore Collection: {collection.name}",
                recommendation=(
                    "Review security rules to ensure they follow the principle of least privilege. "
                    "Typically, authenticated users should have equal or greater access than anonymous users."
                ),
                evidence={
                    "collection": collection.name,
                    "readable_anon": True,
                    "readable_auth": False,
                },
                cwe="CWE-732: Incorrect Permission Assignment",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.FIRESTORE,
            )
            findings.append(finding)

        return findings

    def _test_data_exposure(self, collection: FirestoreCollection) -> List[SecurityFinding]:
        """
        Test for sensitive data exposure in accessible collections.

        Args:
            collection: FirestoreCollection to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if not collection.readable_anon or not collection.sample_documents:
            return findings

        # Check for sensitive field names in documents
        sensitive_fields = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apiKey",
            "private_key",
            "privateKey",
            "ssn",
            "credit_card",
            "creditCard",
            "cvv",
            "pin",
            "salt",
            "hash",
        }

        exposed_fields = set()
        for doc in collection.sample_documents:
            if isinstance(doc, dict) and "fields" in doc:
                # Firebase REST API format
                fields = doc["fields"]
                for field_name in fields.keys():
                    if field_name.lower() in sensitive_fields or any(
                        sf in field_name.lower() for sf in sensitive_fields
                    ):
                        exposed_fields.add(field_name)

        if exposed_fields:
            finding = SecurityFinding(
                severity=Severity.HIGH,
                title=f'Sensitive Data Exposed in Collection "{collection.name}"',
                description=(
                    f"The publicly readable collection '{collection.name}' contains documents "
                    f"with potentially sensitive fields: {', '.join(exposed_fields)}. "
                    "This data should not be accessible to anonymous users."
                ),
                affected_resource=f"Firestore Collection: {collection.name}",
                recommendation=(
                    "1. Move sensitive data to a separate, protected collection\n"
                    "2. Add security rules to restrict access to authenticated users\n"
                    "3. Use Firebase Security Rules to filter sensitive fields:\n"
                    f"match /databases/{{database}}/documents/{collection.name}/{{document}} {{\n"
                    "  allow read: if request.auth != null && request.auth.uid == resource.data.userId;\n"
                    "}"
                ),
                evidence={
                    "collection": collection.name,
                    "sensitive_fields": list(exposed_fields),
                    "document_count": collection.document_count,
                },
                cwe="CWE-359: Exposure of Private Information",
                owasp="API3:2023 Broken Object Property Level Authorization",
                resource_type=ResourceType.FIRESTORE,
            )
            findings.append(finding)

        return findings
