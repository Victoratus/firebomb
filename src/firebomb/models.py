"""
Data models for Firebomb.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Security finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResourceType(str, Enum):
    """Firebase resource types."""

    FIRESTORE = "firestore"
    RTDB = "realtime_database"
    STORAGE = "storage"
    FUNCTIONS = "functions"
    AUTH = "authentication"
    HOSTING = "hosting"


@dataclass
class SecurityFinding:
    """Represents a security finding from testing."""

    severity: Severity
    title: str
    description: str
    affected_resource: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe: str = ""
    owasp: str = ""
    resource_type: Optional[ResourceType] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_resource": self.affected_resource,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "resource_type": self.resource_type.value if self.resource_type else None,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class FirebaseConfig:
    """Firebase project configuration."""

    project_id: str
    api_key: str
    auth_domain: Optional[str] = None
    database_url: Optional[str] = None
    storage_bucket: Optional[str] = None
    messaging_sender_id: Optional[str] = None
    app_id: Optional[str] = None
    measurement_id: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    source_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_id": self.project_id,
            "api_key": self.api_key,
            "auth_domain": self.auth_domain,
            "database_url": self.database_url,
            "storage_bucket": self.storage_bucket,
            "messaging_sender_id": self.messaging_sender_id,
            "app_id": self.app_id,
            "measurement_id": self.measurement_id,
            "discovered_at": self.discovered_at.isoformat(),
            "source_url": self.source_url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FirebaseConfig":
        """Create from dictionary."""
        discovered_at = data.get("discovered_at")
        if discovered_at and isinstance(discovered_at, str):
            discovered_at = datetime.fromisoformat(discovered_at)
        elif not discovered_at:
            discovered_at = datetime.now()

        return cls(
            project_id=data["project_id"],
            api_key=data["api_key"],
            auth_domain=data.get("auth_domain"),
            database_url=data.get("database_url"),
            storage_bucket=data.get("storage_bucket"),
            messaging_sender_id=data.get("messaging_sender_id"),
            app_id=data.get("app_id"),
            measurement_id=data.get("measurement_id"),
            discovered_at=discovered_at,
            source_url=data.get("source_url"),
        )


@dataclass
class FirestoreCollection:
    """Represents a Firestore collection."""

    name: str
    document_count: int
    readable_anon: bool = False
    writable_anon: bool = False
    readable_auth: bool = False
    writable_auth: bool = False
    sample_documents: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RTDBPath:
    """Represents a Realtime Database path."""

    path: str
    readable: bool = False
    writable: bool = False
    data_sample: Optional[Any] = None


@dataclass
class StorageBucket:
    """Represents a Cloud Storage bucket."""

    name: str
    public_read: bool = False
    public_write: bool = False
    files_count: int = 0
    sample_files: List[str] = field(default_factory=list)


@dataclass
class CloudFunction:
    """Represents a Cloud Function."""

    name: str
    url: str
    requires_auth: bool = True
    allows_cors: bool = False
    response_sample: Optional[Dict[str, Any]] = None


@dataclass
class AuthConfig:
    """Authentication configuration."""

    email_password_enabled: bool = False
    google_oauth_enabled: bool = False
    anonymous_enabled: bool = False
    email_verification_required: bool = False
    password_policy_strength: str = "unknown"
    providers: List[str] = field(default_factory=list)


@dataclass
class EnumerationResult:
    """Results from resource enumeration."""

    firestore_collections: List[FirestoreCollection] = field(default_factory=list)
    rtdb_paths: List[RTDBPath] = field(default_factory=list)
    storage_buckets: List[StorageBucket] = field(default_factory=list)
    cloud_functions: List[CloudFunction] = field(default_factory=list)
    auth_config: Optional[AuthConfig] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "firestore_collections": [
                {
                    "name": col.name,
                    "document_count": col.document_count,
                    "readable_anon": col.readable_anon,
                    "writable_anon": col.writable_anon,
                    "readable_auth": col.readable_auth,
                    "writable_auth": col.writable_auth,
                }
                for col in self.firestore_collections
            ],
            "rtdb_paths": [
                {"path": path.path, "readable": path.readable, "writable": path.writable}
                for path in self.rtdb_paths
            ],
            "storage_buckets": [
                {
                    "name": bucket.name,
                    "public_read": bucket.public_read,
                    "public_write": bucket.public_write,
                    "files_count": bucket.files_count,
                }
                for bucket in self.storage_buckets
            ],
            "cloud_functions": [
                {
                    "name": func.name,
                    "url": func.url,
                    "requires_auth": func.requires_auth,
                    "allows_cors": func.allows_cors,
                }
                for func in self.cloud_functions
            ],
            "auth_config": {
                "email_password_enabled": self.auth_config.email_password_enabled,
                "google_oauth_enabled": self.auth_config.google_oauth_enabled,
                "anonymous_enabled": self.auth_config.anonymous_enabled,
                "email_verification_required": self.auth_config.email_verification_required,
                "password_policy_strength": self.auth_config.password_policy_strength,
                "providers": self.auth_config.providers,
            }
            if self.auth_config
            else None,
            "timestamp": self.timestamp.isoformat(),
        }
