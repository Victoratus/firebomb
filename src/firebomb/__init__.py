"""
Firebomb: Firebase Security Testing Tool

A comprehensive CLI tool for Firebase security assessment and penetration testing.
"""

__version__ = "1.0.0"
__author__ = "Víctor Yrazusta"
__license__ = "MIT"

from firebomb.models import SecurityFinding, FirebaseConfig

__all__ = ["SecurityFinding", "FirebaseConfig", "__version__"]
