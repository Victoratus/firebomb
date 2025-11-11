"""
Cloud Storage security testing.
"""

from typing import List
from firebomb.client import FirebaseClient
from firebomb.models import SecurityFinding, Severity, ResourceType, StorageBucket


class StorageTester:
    """Tests Cloud Storage security configurations."""

    def __init__(self, client: FirebaseClient):
        """
        Initialize Storage tester.

        Args:
            client: FirebaseClient instance
        """
        self.client = client

    def test(self, buckets: List[StorageBucket]) -> List[SecurityFinding]:
        """
        Run all Cloud Storage security tests.

        Args:
            buckets: List of StorageBucket objects to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        for bucket in buckets:
            findings.extend(self._test_public_read(bucket))
            findings.extend(self._test_public_write(bucket))
            findings.extend(self._test_file_exposure(bucket))

        return findings

    def _test_public_read(self, bucket: StorageBucket) -> List[SecurityFinding]:
        """
        Test for publicly readable buckets.

        Args:
            bucket: StorageBucket to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if bucket.public_read and bucket.files_count > 0:
            finding = SecurityFinding(
                severity=Severity.HIGH,
                title=f'Cloud Storage Bucket "{bucket.name}" Publicly Readable',
                description=(
                    f"The Cloud Storage bucket '{bucket.name}' allows anonymous read access. "
                    f"Anyone can list and download {bucket.files_count} files from this bucket "
                    "without authentication. This may expose sensitive user data or application files."
                ),
                affected_resource=f"Cloud Storage Bucket: {bucket.name}",
                recommendation=(
                    "Update storage security rules to restrict read access:\n"
                    "service firebase.storage {\n"
                    f"  match /b/{bucket.name}/o {{\n"
                    "    match /{allPaths=**} {\n"
                    "      allow read: if request.auth != null;\n"
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                evidence={
                    "bucket": bucket.name,
                    "public_read": True,
                    "files_count": bucket.files_count,
                    "sample_files": bucket.sample_files[:5],
                },
                cwe="CWE-284: Improper Access Control",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.STORAGE,
            )
            findings.append(finding)

        return findings

    def _test_public_write(self, bucket: StorageBucket) -> List[SecurityFinding]:
        """
        Test for publicly writable buckets.

        Args:
            bucket: StorageBucket to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if bucket.public_write:
            finding = SecurityFinding(
                severity=Severity.CRITICAL,
                title=f'Cloud Storage Bucket "{bucket.name}" Publicly Writable',
                description=(
                    f"The Cloud Storage bucket '{bucket.name}' allows anonymous write access. "
                    "Anyone can upload, modify, or delete files without authentication. "
                    "This is a critical vulnerability that could lead to:\n"
                    "- Malware uploads\n"
                    "- Data tampering\n"
                    "- Resource exhaustion\n"
                    "- Storage cost abuse"
                ),
                affected_resource=f"Cloud Storage Bucket: {bucket.name}",
                recommendation=(
                    "Update storage security rules to restrict write access:\n"
                    "service firebase.storage {\n"
                    f"  match /b/{bucket.name}/o {{\n"
                    "    match /{allPaths=**} {\n"
                    "      allow write: if request.auth != null && request.auth.uid == resource.metadata.uploaderId;\n"
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                evidence={"bucket": bucket.name, "public_write": True},
                cwe="CWE-284: Improper Access Control",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.STORAGE,
            )
            findings.append(finding)

        return findings

    def _test_file_exposure(self, bucket: StorageBucket) -> List[SecurityFinding]:
        """
        Test for sensitive file exposure.

        Args:
            bucket: StorageBucket to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if not bucket.public_read or not bucket.sample_files:
            return findings

        # Check for sensitive file patterns
        sensitive_patterns = {
            ".env": "Environment configuration",
            "config.": "Configuration file",
            ".key": "Private key",
            ".pem": "Certificate/key file",
            ".json": "Credentials or config",
            "secret": "Secret data",
            "password": "Password file",
            "credentials": "Credentials file",
            "token": "Authentication token",
            "backup": "Backup file",
            ".db": "Database file",
            ".sql": "Database dump",
            "id_rsa": "SSH private key",
            ".p12": "Certificate file",
            ".pfx": "Certificate file",
        }

        exposed_files = []
        for file_path in bucket.sample_files:
            file_lower = file_path.lower()
            for pattern, description in sensitive_patterns.items():
                if pattern in file_lower:
                    exposed_files.append({"file": file_path, "type": description})
                    break

        if exposed_files:
            finding = SecurityFinding(
                severity=Severity.HIGH,
                title=f'Potentially Sensitive Files Exposed in Bucket "{bucket.name}"',
                description=(
                    f"The publicly accessible bucket '{bucket.name}' contains files that may be sensitive:\n"
                    + "\n".join([f"- {f['file']} ({f['type']})" for f in exposed_files[:5]])
                    + (f"\n...and {len(exposed_files) - 5} more" if len(exposed_files) > 5 else "")
                ),
                affected_resource=f"Cloud Storage Bucket: {bucket.name}",
                recommendation=(
                    "1. Review and remove sensitive files from public storage\n"
                    "2. Move sensitive files to a protected bucket or path\n"
                    "3. Update storage security rules:\n"
                    "service firebase.storage {\n"
                    f"  match /b/{bucket.name}/o {{\n"
                    "    match /sensitive/{allPaths=**} {\n"
                    "      allow read: if request.auth != null && request.auth.uid == resource.metadata.uploaderId;\n"
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                evidence={
                    "bucket": bucket.name,
                    "exposed_files": exposed_files[:10],
                    "total_exposed": len(exposed_files),
                },
                cwe="CWE-359: Exposure of Private Information",
                owasp="API3:2023 Broken Object Property Level Authorization",
                resource_type=ResourceType.STORAGE,
            )
            findings.append(finding)

        return findings
