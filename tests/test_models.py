"""
Tests for data models.
"""

import pytest
from datetime import datetime
from firebomb.models import (
    SecurityFinding,
    FirebaseConfig,
    Severity,
    ResourceType,
    FirestoreCollection,
    RTDBPath,
    StorageBucket,
)


def test_security_finding_creation():
    """Test creating a SecurityFinding."""
    finding = SecurityFinding(
        severity=Severity.HIGH,
        title="Test Finding",
        description="Test description",
        affected_resource="test/resource",
        recommendation="Fix it",
        cwe="CWE-284",
        owasp="API1:2023",
        resource_type=ResourceType.FIRESTORE,
    )

    assert finding.severity == Severity.HIGH
    assert finding.title == "Test Finding"
    assert finding.cwe == "CWE-284"


def test_security_finding_to_dict():
    """Test SecurityFinding serialization."""
    finding = SecurityFinding(
        severity=Severity.CRITICAL,
        title="Critical Issue",
        description="Description",
        affected_resource="resource",
        recommendation="Fix",
    )

    result = finding.to_dict()
    assert result["severity"] == "critical"
    assert result["title"] == "Critical Issue"
    assert "timestamp" in result


def test_firebase_config_creation():
    """Test creating a FirebaseConfig."""
    config = FirebaseConfig(
        project_id="test-project",
        api_key="AIzaSyTest1234567890123456789012345",
        auth_domain="test-project.firebaseapp.com",
        database_url="https://test-project.firebaseio.com",
        storage_bucket="test-project.appspot.com",
    )

    assert config.project_id == "test-project"
    assert config.api_key.startswith("AIza")
    assert config.database_url == "https://test-project.firebaseio.com"


def test_firebase_config_to_dict():
    """Test FirebaseConfig serialization."""
    config = FirebaseConfig(project_id="test", api_key="test-key")

    result = config.to_dict()
    assert result["project_id"] == "test"
    assert result["api_key"] == "test-key"
    assert "discovered_at" in result


def test_firebase_config_from_dict():
    """Test FirebaseConfig deserialization."""
    data = {
        "project_id": "test-project",
        "api_key": "test-key",
        "auth_domain": "test.firebaseapp.com",
        "discovered_at": datetime.now().isoformat(),
    }

    config = FirebaseConfig.from_dict(data)
    assert config.project_id == "test-project"
    assert config.api_key == "test-key"
    assert config.auth_domain == "test.firebaseapp.com"


def test_firestore_collection():
    """Test FirestoreCollection model."""
    collection = FirestoreCollection(
        name="users", document_count=10, readable_anon=True, writable_anon=False
    )

    assert collection.name == "users"
    assert collection.document_count == 10
    assert collection.readable_anon is True
    assert collection.writable_anon is False


def test_rtdb_path():
    """Test RTDBPath model."""
    path = RTDBPath(path="/users", readable=True, writable=False, data_sample={"test": "data"})

    assert path.path == "/users"
    assert path.readable is True
    assert path.writable is False
    assert path.data_sample == {"test": "data"}


def test_storage_bucket():
    """Test StorageBucket model."""
    bucket = StorageBucket(
        name="test-bucket", public_read=True, public_write=False, files_count=5
    )

    assert bucket.name == "test-bucket"
    assert bucket.public_read is True
    assert bucket.public_write is False
    assert bucket.files_count == 5
