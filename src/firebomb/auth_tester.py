"""
Authentication configuration security testing.
"""

from typing import List, Optional
from firebomb.client import FirebaseClient
from firebomb.models import SecurityFinding, Severity, ResourceType, AuthConfig


class AuthTester:
    """Tests Authentication configuration security."""

    def __init__(self, client: FirebaseClient):
        """
        Initialize Auth tester.

        Args:
            client: FirebaseClient instance
        """
        self.client = client

    def test(self, auth_config: Optional[AuthConfig]) -> List[SecurityFinding]:
        """
        Run all Authentication security tests.

        Args:
            auth_config: AuthConfig object to test

        Returns:
            List of SecurityFinding objects
        """
        if not auth_config:
            return []

        findings = []

        findings.extend(self._test_anonymous_auth(auth_config))
        findings.extend(self._test_email_verification(auth_config))
        findings.extend(self._test_password_policy(auth_config))
        findings.extend(self._test_auth_providers(auth_config))

        return findings

    def _test_anonymous_auth(self, auth_config: AuthConfig) -> List[SecurityFinding]:
        """
        Test if anonymous authentication is enabled.

        Args:
            auth_config: AuthConfig to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if auth_config.anonymous_enabled:
            finding = SecurityFinding(
                severity=Severity.MEDIUM,
                title="Anonymous Authentication Enabled",
                description=(
                    "The Firebase project has anonymous authentication enabled. While this can be "
                    "useful for certain use cases, it allows anyone to create user accounts without "
                    "providing any credentials. This can lead to:\n"
                    "- Spam account creation\n"
                    "- Resource abuse\n"
                    "- Difficulty in user accountability\n"
                    "- Potential for automated attacks\n\n"
                    "Anonymous users may have access to protected resources if security rules are "
                    "not properly configured to distinguish between anonymous and verified users."
                ),
                affected_resource="Firebase Authentication",
                recommendation=(
                    "1. Disable anonymous authentication if not required:\n"
                    "   - Go to Firebase Console > Authentication > Sign-in method\n"
                    "   - Disable the Anonymous provider\n\n"
                    "2. If anonymous auth is required, add security rules to limit anonymous user access:\n\n"
                    "Firestore:\n"
                    "match /databases/{database}/documents/restricted/{doc} {\n"
                    "  allow read, write: if request.auth != null && request.auth.token.firebase.sign_in_provider != 'anonymous';\n"
                    "}\n\n"
                    "Realtime Database:\n"
                    '".read": "auth != null && auth.provider != \'anonymous\'",\n'
                    '".write": "auth != null && auth.provider != \'anonymous\'"'
                ),
                evidence={"anonymous_enabled": True, "providers": auth_config.providers},
                cwe="CWE-287: Improper Authentication",
                owasp="API2:2023 Broken Authentication",
                resource_type=ResourceType.AUTH,
            )
            findings.append(finding)

        return findings

    def _test_email_verification(self, auth_config: AuthConfig) -> List[SecurityFinding]:
        """
        Test if email verification is required.

        Args:
            auth_config: AuthConfig to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if auth_config.email_password_enabled and not auth_config.email_verification_required:
            finding = SecurityFinding(
                severity=Severity.LOW,
                title="Email Verification Not Required",
                description=(
                    "Email/password authentication is enabled but email verification is not enforced. "
                    "This allows users to register with any email address (including fake ones) without "
                    "proving ownership. This can lead to:\n"
                    "- Fake account creation\n"
                    "- Email spoofing\n"
                    "- Reduced user accountability\n"
                    "- Potential for abuse"
                ),
                affected_resource="Firebase Authentication",
                recommendation=(
                    "1. Enable email verification requirement in Firebase Console\n"
                    "2. Add security rules to restrict unverified users:\n\n"
                    "Firestore:\n"
                    "match /databases/{database}/documents/protected/{doc} {\n"
                    "  allow read, write: if request.auth != null && request.auth.token.email_verified == true;\n"
                    "}\n\n"
                    "Realtime Database:\n"
                    '".read": "auth != null && auth.token.email_verified === true",\n'
                    '".write": "auth != null && auth.token.email_verified === true"\n\n'
                    "3. Send verification emails on signup:\n"
                    "firebase.auth().currentUser.sendEmailVerification()"
                ),
                evidence={
                    "email_password_enabled": True,
                    "email_verification_required": False,
                },
                cwe="CWE-287: Improper Authentication",
                owasp="API2:2023 Broken Authentication",
                resource_type=ResourceType.AUTH,
            )
            findings.append(finding)

        return findings

    def _test_password_policy(self, auth_config: AuthConfig) -> List[SecurityFinding]:
        """
        Test password policy strength.

        Args:
            auth_config: AuthConfig to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if auth_config.email_password_enabled:
            # Try to create a user with a weak password to test policy
            weak_password = "123456"
            test_email = f"firebomb_weak_test_{id(self)}@example.com"

            user_id, token, error = self.client.signup_email_password(test_email, weak_password)

            if user_id and token:
                # Weak password was accepted
                finding = SecurityFinding(
                    severity=Severity.MEDIUM,
                    title="Weak Password Policy",
                    description=(
                        "The Firebase project accepts weak passwords. A test registration with "
                        f'the password "{weak_password}" was successful. Weak password policies allow:\n'
                        "- Easy password guessing\n"
                        "- Brute-force attacks\n"
                        "- Credential stuffing\n"
                        "- Account compromise\n\n"
                        "Firebase's default minimum password length is 6 characters, which is "
                        "insufficient by modern security standards."
                    ),
                    affected_resource="Firebase Authentication",
                    recommendation=(
                        "1. Implement client-side password validation:\n"
                        "   - Minimum 12 characters (or 8 with complexity requirements)\n"
                        "   - Mix of uppercase, lowercase, numbers, and symbols\n"
                        "   - Check against common password lists\n\n"
                        "2. Use Firebase's password policy enforcement (if available in your plan):\n"
                        "   - Go to Firebase Console > Authentication > Settings\n"
                        "   - Configure password requirements\n\n"
                        "3. Implement password validation in your app:\n"
                        "function validatePassword(password) {\n"
                        "  const minLength = 12;\n"
                        "  const hasUpperCase = /[A-Z]/.test(password);\n"
                        "  const hasLowerCase = /[a-z]/.test(password);\n"
                        "  const hasNumbers = /\\d/.test(password);\n"
                        "  const hasSymbols = /[!@#$%^&*]/.test(password);\n"
                        "  return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSymbols;\n"
                        "}"
                    ),
                    evidence={
                        "weak_password_accepted": True,
                        "test_password": weak_password,
                        "password_policy_strength": "weak",
                    },
                    cwe="CWE-521: Weak Password Requirements",
                    owasp="API2:2023 Broken Authentication",
                    resource_type=ResourceType.AUTH,
                )
                findings.append(finding)

        return findings

    def _test_auth_providers(self, auth_config: AuthConfig) -> List[SecurityFinding]:
        """
        Test authentication provider configuration.

        Args:
            auth_config: AuthConfig to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        # Check if no authentication methods are enabled
        if not any(
            [
                auth_config.email_password_enabled,
                auth_config.google_oauth_enabled,
                auth_config.anonymous_enabled,
            ]
        ):
            finding = SecurityFinding(
                severity=Severity.INFO,
                title="No Authentication Providers Enabled",
                description=(
                    "No authentication providers appear to be enabled for this Firebase project. "
                    "This is unusual and may indicate that authentication is not properly configured "
                    "or that the project is not yet in production."
                ),
                affected_resource="Firebase Authentication",
                recommendation=(
                    "Enable appropriate authentication providers in Firebase Console:\n"
                    "1. Go to Authentication > Sign-in method\n"
                    "2. Enable providers that match your application's needs\n"
                    "3. Configure security rules to require authentication"
                ),
                evidence={"providers": auth_config.providers},
                cwe="",
                owasp="API2:2023 Broken Authentication",
                resource_type=ResourceType.AUTH,
            )
            findings.append(finding)

        # Info finding about enabled providers
        if auth_config.providers:
            finding = SecurityFinding(
                severity=Severity.INFO,
                title="Authentication Providers Summary",
                description=(
                    "The following authentication providers are enabled:\n"
                    + "\n".join([f"- {provider}" for provider in auth_config.providers])
                    + "\n\nEnsure that:\n"
                    "- Only necessary providers are enabled\n"
                    "- Each provider is properly configured\n"
                    "- Security rules account for different provider types"
                ),
                affected_resource="Firebase Authentication",
                recommendation=(
                    "Review each provider's configuration:\n"
                    "1. Disable any unused providers\n"
                    "2. Configure OAuth providers with proper redirect URIs\n"
                    "3. Implement multi-factor authentication for sensitive operations\n"
                    "4. Add security rules that distinguish between provider types if needed"
                ),
                evidence={"providers": auth_config.providers},
                cwe="",
                owasp="",
                resource_type=ResourceType.AUTH,
            )
            findings.append(finding)

        return findings
