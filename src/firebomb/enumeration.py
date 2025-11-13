"""
Firebase resource enumeration.
"""

from typing import List, Optional
from firebomb.client import FirebaseClient
from firebomb.models import (
    EnumerationResult,
    FirestoreCollection,
    RTDBPath,
    StorageBucket,
    CloudFunction,
    AuthConfig,
)


class FirebaseEnumerator:
    """Enumerates Firebase resources."""

    def __init__(self, client: FirebaseClient):
        """
        Initialize enumerator.

        Args:
            client: FirebaseClient instance
        """
        self.client = client

    def enumerate_all(self) -> EnumerationResult:
        """
        Enumerate all Firebase resources.

        Returns:
            EnumerationResult with all discovered resources
        """
        result = EnumerationResult()

        # Enumerate Firestore
        result.firestore_collections = self.enumerate_firestore()

        # Enumerate Realtime Database
        result.rtdb_paths = self.enumerate_rtdb()

        # Enumerate Cloud Storage
        result.storage_buckets = self.enumerate_storage()

        # Enumerate Cloud Functions (basic discovery)
        result.cloud_functions = self.enumerate_functions()

        # Get authentication config
        result.auth_config = self.enumerate_auth_config()

        return result

    def enumerate_firestore(self) -> List[FirestoreCollection]:
        """
        Enumerate Firestore collections.

        Returns:
            List of FirestoreCollection objects
        """
        collections = []

        # Try to list collections
        collection_names, success = self.client.list_firestore_collections()

        if not success:
            # Try common collection names
            common_collections = [
                "users",
                "posts",
                "products",
                "orders",
                "comments",
                "messages",
                "notifications",
                "settings",
                "profiles",
                "items",
            ]
            collection_names = common_collections

        for collection_name in collection_names:
            # Test anonymous read access
            docs_anon, anon_readable = self.client.read_firestore_collection(
                collection_name, use_auth=False, limit=10
            )

            # Test authenticated read access (if we have auth)
            docs_auth, auth_readable = None, False
            if self.client.auth_token:
                docs_auth, auth_readable = self.client.read_firestore_collection(
                    collection_name, use_auth=True, limit=10
                )

            # Test write access by attempting a write
            test_write_anon, _ = self.client.write_firestore_document(
                collection_name, "__firebomb_test__", {"test": "data"}, use_auth=False
            )

            test_write_auth = False
            if self.client.auth_token:
                test_write_auth, _ = self.client.write_firestore_document(
                    collection_name, "__firebomb_test__", {"test": "data"}, use_auth=True
                )

            # Count documents
            doc_count = 0
            sample_docs = []
            if docs_anon:
                doc_count = len(docs_anon)
                sample_docs = docs_anon[:3]  # Keep first 3 as samples
            elif docs_auth:
                doc_count = len(docs_auth)
                sample_docs = docs_auth[:3]

            collection = FirestoreCollection(
                name=collection_name,
                document_count=doc_count,
                readable_anon=anon_readable,
                writable_anon=test_write_anon,
                readable_auth=auth_readable,
                writable_auth=test_write_auth,
                sample_documents=sample_docs,
            )
            collections.append(collection)

        return collections

    def enumerate_rtdb(self) -> List[RTDBPath]:
        """
        Enumerate Realtime Database paths.

        Returns:
            List of RTDBPath objects
        """
        paths = []

        # Try common root paths
        common_paths = [
            "/",
            "/users",
            "/posts",
            "/messages",
            "/data",
            "/public",
            "/config",
            "/settings",
            "/profiles",
            "/items",
        ]

        for path in common_paths:
            # Test read access
            data, readable = self.client.read_rtdb_path(path, use_auth=False)

            # Test write access
            writable, _ = self.client.write_rtdb_path(
                f"{path}/__firebomb_test__", {"test": "data"}, use_auth=False
            )

            if readable or writable:
                rtdb_path = RTDBPath(
                    path=path, readable=readable, writable=writable, data_sample=data if readable else None
                )
                paths.append(rtdb_path)

                # If root is readable, try to enumerate children
                if path == "/" and readable and isinstance(data, dict):
                    for child_key in list(data.keys())[:10]:  # Limit to first 10 children
                        child_path = f"/{child_key}"
                        if child_path not in common_paths:
                            child_data, child_readable = self.client.read_rtdb_path(
                                child_path, use_auth=False
                            )
                            if child_readable:
                                paths.append(
                                    RTDBPath(
                                        path=child_path,
                                        readable=child_readable,
                                        writable=False,
                                        data_sample=child_data,
                                    )
                                )

        return paths

    def enumerate_storage(self) -> List[StorageBucket]:
        """
        Enumerate Cloud Storage buckets.

        Returns:
            List of StorageBucket objects
        """
        buckets = []

        if not self.client.storage_bucket:
            return buckets

        # Try to list files in the bucket
        file_names, success = self.client.list_storage_bucket(use_auth=False)

        public_read = success
        files_count = len(file_names) if success else 0

        # Test write access by attempting to read a file (if any exist)
        public_write = False
        sample_files = []
        if file_names:
            sample_files = file_names[:5]  # Keep first 5 as samples
            # Try to read the first file
            can_read, _ = self.client.read_storage_file(file_names[0], use_auth=False)
            public_read = public_read and can_read

        bucket = StorageBucket(
            name=self.client.storage_bucket,
            public_read=public_read,
            public_write=public_write,
            files_count=files_count,
            sample_files=sample_files,
        )
        buckets.append(bucket)

        return buckets

    def enumerate_functions(self) -> List[CloudFunction]:
        """
        Enumerate Cloud Functions (basic discovery).

        Returns:
            List of CloudFunction objects
        """
        functions = []

        # Common function names to try
        common_functions = [
            "sendEmail",
            "processPayment",
            "createUser",
            "deleteUser",
            "uploadFile",
            "generateReport",
            "sendNotification",
            "webhook",
            "api",
            "hello",
            "test",
        ]

        for func_name in common_functions:
            # Try to invoke without auth
            response, status_code = self.client.invoke_function(func_name, use_auth=False)

            if status_code != 0 and status_code != 404:
                # Function exists
                requires_auth = status_code == 401 or status_code == 403
                url = f"{self.client.functions_base}/{func_name}"

                function = CloudFunction(
                    name=func_name,
                    url=url,
                    requires_auth=requires_auth,
                    allows_cors=False,  # Would need to check headers
                    response_sample=response,
                )
                functions.append(function)

        return functions

    def enumerate_auth_config(self) -> Optional[AuthConfig]:
        """
        Enumerate authentication configuration.

        Returns:
            AuthConfig object or None
        """
        config_data, success = self.client.get_auth_config()

        if not success or not config_data:
            # Try to infer from signup attempts
            return self._infer_auth_config()

        # Parse the config
        providers = config_data.get("signIn", {}).get("allowedProviders", [])

        auth_config = AuthConfig(
            email_password_enabled="password" in providers,
            google_oauth_enabled="google.com" in providers,
            anonymous_enabled="anonymous" in providers,
            email_verification_required=False,  # Would need more testing
            password_policy_strength="unknown",
            providers=providers,
        )

        return auth_config

    def _infer_auth_config(self) -> AuthConfig:
        """
        Infer authentication configuration by testing signup methods.

        Returns:
            AuthConfig object
        """
        # Test anonymous signup
        user_id, token = self.client.signup_anonymous()
        anonymous_enabled = user_id is not None

        # Test email/password signup
        test_email = "firebomb_test@example.com"
        test_password = "Test123!"
        user_id, token, error = self.client.signup_email_password(test_email, test_password)
        email_password_enabled = error != "EMAIL_NOT_ALLOWED" if error else True

        return AuthConfig(
            email_password_enabled=email_password_enabled,
            google_oauth_enabled=False,  # Can't test without OAuth flow
            anonymous_enabled=anonymous_enabled,
            email_verification_required=False,
            password_policy_strength="unknown",
            providers=[],
        )
