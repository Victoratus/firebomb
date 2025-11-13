"""
Firebase client wrapper for security testing.
Uses Firebase REST APIs for anonymous testing.
"""

import requests
from typing import Dict, Any, Optional, List, Tuple
import json
from urllib.parse import quote


class FirebaseClient:
    """
    Wrapper for Firebase REST APIs.
    Supports Firestore, Realtime Database, Storage, and Authentication.
    """

    def __init__(self, config: Dict[str, str], auth_token: Optional[str] = None):
        """
        Initialize Firebase client.

        Args:
            config: Firebase configuration dictionary
            auth_token: Optional authentication token for authenticated requests
        """
        self.project_id = config.get("project_id")
        self.api_key = config.get("api_key")
        self.auth_domain = config.get("auth_domain")
        self.database_url = config.get("database_url")
        self.storage_bucket = config.get("storage_bucket")
        self.auth_token = auth_token

        # API endpoints
        self.firestore_base = (
            f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)"
        )
        self.rtdb_base = self.database_url
        self.storage_base = f"https://storage.googleapis.com/storage/v1/b/{self.storage_bucket}"
        self.auth_base = f"https://identitytoolkit.googleapis.com/v1"
        self.functions_base = (
            f"https://{config.get('region', 'us-central1')}-{self.project_id}.cloudfunctions.net"
        )

    def _get_headers(self, use_auth: bool = False) -> Dict[str, str]:
        """
        Get HTTP headers for requests.

        Args:
            use_auth: Whether to include authentication token

        Returns:
            Headers dictionary
        """
        headers = {"Content-Type": "application/json"}
        if use_auth and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    # Firestore methods
    def list_firestore_collections(self) -> Tuple[List[str], bool]:
        """
        Attempt to list Firestore collections.

        Returns:
            Tuple of (list of collection names, success boolean)
        """
        try:
            url = f"{self.firestore_base}/documents"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                collections = []
                if "documents" in data:
                    # Extract collection names from document paths
                    for doc in data["documents"]:
                        path_parts = doc["name"].split("/documents/")
                        if len(path_parts) > 1:
                            collection = path_parts[1].split("/")[0]
                            if collection not in collections:
                                collections.append(collection)
                return collections, True
            return [], False
        except Exception as e:
            return [], False

    def read_firestore_collection(
        self, collection: str, use_auth: bool = False, limit: int = 10
    ) -> Tuple[Optional[List[Dict[str, Any]]], bool]:
        """
        Attempt to read documents from a Firestore collection.

        Args:
            collection: Collection name
            use_auth: Whether to use authentication
            limit: Maximum number of documents to retrieve

        Returns:
            Tuple of (list of documents or None, success boolean)
        """
        try:
            url = f"{self.firestore_base}/documents/{collection}"
            params = {"pageSize": limit}
            if not use_auth and self.api_key:
                params["key"] = self.api_key

            headers = self._get_headers(use_auth)
            response = requests.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                documents = data.get("documents", [])
                return documents, True
            elif response.status_code == 403:
                return None, False
            return None, False
        except Exception as e:
            return None, False

    def write_firestore_document(
        self, collection: str, document_id: str, data: Dict[str, Any], use_auth: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Attempt to write a document to Firestore.

        Args:
            collection: Collection name
            document_id: Document ID
            data: Document data
            use_auth: Whether to use authentication

        Returns:
            Tuple of (success boolean, error message or None)
        """
        try:
            url = f"{self.firestore_base}/documents/{collection}/{document_id}"
            params = {}
            if not use_auth and self.api_key:
                params["key"] = self.api_key

            # Convert data to Firestore format
            firestore_data = {"fields": {}}
            for key, value in data.items():
                firestore_data["fields"][key] = {"stringValue": str(value)}

            headers = self._get_headers(use_auth)
            response = requests.patch(
                url, params=params, json=firestore_data, headers=headers, timeout=10
            )

            if response.status_code in [200, 201]:
                return True, None
            else:
                return False, response.text
        except Exception as e:
            return False, str(e)

    # Realtime Database methods
    def read_rtdb_path(
        self, path: str, use_auth: bool = False
    ) -> Tuple[Optional[Any], bool]:
        """
        Attempt to read data from a Realtime Database path.

        Args:
            path: Database path (e.g., "/users")
            use_auth: Whether to use authentication

        Returns:
            Tuple of (data or None, success boolean)
        """
        try:
            if not self.rtdb_base:
                return None, False

            # Clean up path
            path = path.strip("/")
            url = f"{self.rtdb_base}/{path}.json"

            params = {}
            if not use_auth and self.api_key:
                params["auth"] = self.api_key
            elif use_auth and self.auth_token:
                params["auth"] = self.auth_token

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return data, True
            elif response.status_code == 401:
                return None, False
            return None, False
        except Exception as e:
            return None, False

    def write_rtdb_path(
        self, path: str, data: Any, use_auth: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Attempt to write data to a Realtime Database path.

        Args:
            path: Database path
            data: Data to write
            use_auth: Whether to use authentication

        Returns:
            Tuple of (success boolean, error message or None)
        """
        try:
            if not self.rtdb_base:
                return False, "No database URL configured"

            path = path.strip("/")
            url = f"{self.rtdb_base}/{path}.json"

            params = {}
            if not use_auth and self.api_key:
                params["auth"] = self.api_key
            elif use_auth and self.auth_token:
                params["auth"] = self.auth_token

            response = requests.put(url, params=params, json=data, timeout=10)

            if response.status_code == 200:
                return True, None
            else:
                return False, response.text
        except Exception as e:
            return False, str(e)

    # Cloud Storage methods
    def list_storage_bucket(self, use_auth: bool = False) -> Tuple[List[str], bool]:
        """
        Attempt to list files in a Cloud Storage bucket.

        Args:
            use_auth: Whether to use authentication

        Returns:
            Tuple of (list of file names, success boolean)
        """
        try:
            if not self.storage_bucket:
                return [], False

            url = f"{self.storage_base}/o"
            params = {}
            if not use_auth and self.api_key:
                params["key"] = self.api_key

            headers = self._get_headers(use_auth)
            response = requests.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                file_names = [item.get("name") for item in items if item.get("name")]
                return file_names, True
            return [], False
        except Exception as e:
            return [], False

    def read_storage_file(
        self, file_path: str, use_auth: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Attempt to read a file from Cloud Storage.

        Args:
            file_path: Path to file in bucket
            use_auth: Whether to use authentication

        Returns:
            Tuple of (success boolean, error message or None)
        """
        try:
            if not self.storage_bucket:
                return False, "No storage bucket configured"

            encoded_path = quote(file_path, safe="")
            url = f"{self.storage_base}/o/{encoded_path}"
            params = {"alt": "media"}
            if not use_auth and self.api_key:
                params["key"] = self.api_key

            headers = self._get_headers(use_auth)
            response = requests.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                return True, None
            else:
                return False, response.text
        except Exception as e:
            return False, str(e)

    # Authentication methods
    def signup_anonymous(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Sign up as an anonymous user.

        Returns:
            Tuple of (user ID or None, ID token or None)
        """
        try:
            url = f"{self.auth_base}/accounts:signUp"
            params = {"key": self.api_key}
            data = {"returnSecureToken": True}

            response = requests.post(url, params=params, json=data, timeout=10)

            if response.status_code == 200:
                result = response.json()
                return result.get("localId"), result.get("idToken")
            return None, None
        except Exception as e:
            return None, None

    def signup_email_password(
        self, email: str, password: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Sign up with email and password.

        Args:
            email: Email address
            password: Password

        Returns:
            Tuple of (user ID or None, ID token or None, error message or None)
        """
        try:
            url = f"{self.auth_base}/accounts:signUp"
            params = {"key": self.api_key}
            data = {"email": email, "password": password, "returnSecureToken": True}

            response = requests.post(url, params=params, json=data, timeout=10)

            if response.status_code == 200:
                result = response.json()
                return result.get("localId"), result.get("idToken"), None
            else:
                error = response.json().get("error", {}).get("message", "Unknown error")
                return None, None, error
        except Exception as e:
            return None, None, str(e)

    def get_auth_config(self) -> Tuple[Optional[Dict[str, Any]], bool]:
        """
        Get authentication configuration.

        Returns:
            Tuple of (config dict or None, success boolean)
        """
        try:
            url = f"{self.auth_base}/projects/{self.project_id}/config"
            params = {"key": self.api_key}

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                return response.json(), True
            return None, False
        except Exception as e:
            return None, False

    # Cloud Functions methods
    def invoke_function(
        self, function_name: str, data: Optional[Dict[str, Any]] = None, use_auth: bool = False
    ) -> Tuple[Optional[Dict[str, Any]], int]:
        """
        Attempt to invoke a Cloud Function.

        Args:
            function_name: Function name
            data: Optional data to send
            use_auth: Whether to use authentication

        Returns:
            Tuple of (response data or None, status code)
        """
        try:
            url = f"{self.functions_base}/{function_name}"
            headers = self._get_headers(use_auth)

            response = requests.post(url, json=data or {}, headers=headers, timeout=10)

            if response.status_code == 200:
                try:
                    return response.json(), response.status_code
                except json.JSONDecodeError:
                    return {"response": response.text}, response.status_code
            return None, response.status_code
        except Exception as e:
            return None, 0
