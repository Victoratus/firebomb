"""
Credential caching management for Firebomb.
"""

from typing import Optional, List, Dict, Any
from firebomb.models import FirebaseConfig
from firebomb.utils import get_cache_path, load_cache, save_cache


class CredentialCache:
    """Manages cached Firebase credentials."""

    def __init__(self):
        self.cache_path = get_cache_path()
        self._cache = load_cache()

    def add(self, config: FirebaseConfig) -> None:
        """
        Add a Firebase configuration to the cache.

        Args:
            config: Firebase configuration to cache
        """
        self._cache[config.project_id] = config.to_dict()
        save_cache(self._cache)

    def get(self, project_id: str) -> Optional[FirebaseConfig]:
        """
        Get a cached Firebase configuration.

        Args:
            project_id: Project ID to retrieve

        Returns:
            FirebaseConfig if found, None otherwise
        """
        config_data = self._cache.get(project_id)
        if config_data:
            return FirebaseConfig.from_dict(config_data)
        return None

    def remove(self, project_id: str) -> bool:
        """
        Remove a Firebase configuration from the cache.

        Args:
            project_id: Project ID to remove

        Returns:
            True if removed, False if not found
        """
        if project_id in self._cache:
            del self._cache[project_id]
            save_cache(self._cache)
            return True
        return False

    def list(self) -> List[FirebaseConfig]:
        """
        List all cached Firebase configurations.

        Returns:
            List of FirebaseConfig objects
        """
        configs = []
        for project_id, config_data in self._cache.items():
            try:
                configs.append(FirebaseConfig.from_dict(config_data))
            except (KeyError, TypeError):
                # Skip invalid cache entries
                continue
        return configs

    def clear(self) -> None:
        """Clear all cached configurations."""
        self._cache = {}
        save_cache(self._cache)

    def exists(self, project_id: str) -> bool:
        """
        Check if a project exists in the cache.

        Args:
            project_id: Project ID to check

        Returns:
            True if exists, False otherwise
        """
        return project_id in self._cache

    def get_all(self) -> Dict[str, Any]:
        """
        Get all cached configurations as a dictionary.

        Returns:
            Dictionary of all cached configurations
        """
        return self._cache.copy()
