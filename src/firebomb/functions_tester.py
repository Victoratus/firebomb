"""
Cloud Functions security testing.
"""

from typing import List
from firebomb.client import FirebaseClient
from firebomb.models import SecurityFinding, Severity, ResourceType, CloudFunction


class FunctionsTester:
    """Tests Cloud Functions security configurations."""

    def __init__(self, client: FirebaseClient):
        """
        Initialize Functions tester.

        Args:
            client: FirebaseClient instance
        """
        self.client = client

    def test(self, functions: List[CloudFunction]) -> List[SecurityFinding]:
        """
        Run all Cloud Functions security tests.

        Args:
            functions: List of CloudFunction objects to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        for function in functions:
            findings.extend(self._test_unauthenticated_access(function))
            findings.extend(self._test_cors_misconfiguration(function))
            findings.extend(self._test_information_disclosure(function))

        return findings

    def _test_unauthenticated_access(self, function: CloudFunction) -> List[SecurityFinding]:
        """
        Test for functions accessible without authentication.

        Args:
            function: CloudFunction to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if not function.requires_auth and function.response_sample is not None:
            # Determine severity based on function name and response
            severity = self._assess_function_severity(function)

            finding = SecurityFinding(
                severity=severity,
                title=f'Cloud Function "{function.name}" Accessible Without Authentication',
                description=(
                    f"The Cloud Function '{function.name}' can be invoked without authentication. "
                    "This function is publicly accessible and may expose sensitive operations or data. "
                    "Depending on the function's purpose, this could allow unauthorized users to:\n"
                    "- Access sensitive data\n"
                    "- Trigger costly operations\n"
                    "- Manipulate application state\n"
                    "- Exploit business logic"
                ),
                affected_resource=f"Cloud Function: {function.name}",
                recommendation=(
                    "Add authentication checks to the function:\n\n"
                    "JavaScript:\n"
                    "exports." + function.name + " = functions.https.onCall((data, context) => {\n"
                    "  if (!context.auth) {\n"
                    "    throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated');\n"
                    "  }\n"
                    "  // Function logic here\n"
                    "});\n\n"
                    "Or configure IAM to require authentication:\n"
                    f"gcloud functions add-iam-policy-binding {function.name} \\\n"
                    "  --member='allUsers' \\\n"
                    "  --role='roles/cloudfunctions.invoker' \\\n"
                    "  --remove"
                ),
                evidence={
                    "function": function.name,
                    "url": function.url,
                    "requires_auth": False,
                    "response_sample": self._truncate_response(function.response_sample),
                },
                cwe="CWE-306: Missing Authentication for Critical Function",
                owasp="API1:2023 Broken Object Level Authorization",
                resource_type=ResourceType.FUNCTIONS,
            )
            findings.append(finding)

        return findings

    def _test_cors_misconfiguration(self, function: CloudFunction) -> List[SecurityFinding]:
        """
        Test for CORS misconfigurations.

        Args:
            function: CloudFunction to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if function.allows_cors:
            finding = SecurityFinding(
                severity=Severity.MEDIUM,
                title=f'Cloud Function "{function.name}" Has Permissive CORS Policy',
                description=(
                    f"The Cloud Function '{function.name}' allows cross-origin requests (CORS). "
                    "If the CORS policy is overly permissive (e.g., Access-Control-Allow-Origin: *), "
                    "it may allow malicious websites to make requests to this function from users' browsers."
                ),
                affected_resource=f"Cloud Function: {function.name}",
                recommendation=(
                    "Configure CORS to only allow trusted origins:\n\n"
                    "exports." + function.name + " = functions.https.onRequest((req, res) => {\n"
                    "  const allowedOrigins = ['https://yourdomain.com'];\n"
                    "  const origin = req.headers.origin;\n"
                    "  if (allowedOrigins.includes(origin)) {\n"
                    "    res.set('Access-Control-Allow-Origin', origin);\n"
                    "  }\n"
                    "  // Function logic here\n"
                    "});"
                ),
                evidence={"function": function.name, "url": function.url, "allows_cors": True},
                cwe="CWE-346: Origin Validation Error",
                owasp="API7:2023 Server Side Request Forgery",
                resource_type=ResourceType.FUNCTIONS,
            )
            findings.append(finding)

        return findings

    def _test_information_disclosure(self, function: CloudFunction) -> List[SecurityFinding]:
        """
        Test for information disclosure in function responses.

        Args:
            function: CloudFunction to test

        Returns:
            List of SecurityFinding objects
        """
        findings = []

        if not function.response_sample:
            return findings

        # Check for sensitive information in responses
        response_str = str(function.response_sample).lower()
        sensitive_indicators = {
            "error": "Error messages",
            "stack": "Stack traces",
            "exception": "Exception details",
            "password": "Password references",
            "secret": "Secret references",
            "token": "Token references",
            "key": "Key references",
            "credential": "Credential references",
            "internal": "Internal implementation details",
        }

        found_indicators = []
        for indicator, description in sensitive_indicators.items():
            if indicator in response_str:
                found_indicators.append(description)

        if found_indicators:
            finding = SecurityFinding(
                severity=Severity.LOW,
                title=f'Cloud Function "{function.name}" May Expose Sensitive Information',
                description=(
                    f"The Cloud Function '{function.name}' response may contain sensitive information:\n"
                    + "\n".join([f"- {ind}" for ind in found_indicators])
                    + "\n\nThis could help attackers understand the application's internal workings."
                ),
                affected_resource=f"Cloud Function: {function.name}",
                recommendation=(
                    "1. Sanitize error messages before returning them\n"
                    "2. Avoid exposing stack traces in production\n"
                    "3. Use generic error messages for users\n"
                    "4. Log detailed errors server-side only\n"
                    "5. Implement proper error handling:\n\n"
                    "try {\n"
                    "  // Function logic\n"
                    "} catch (error) {\n"
                    "  console.error('Function error:', error); // Log internally\n"
                    "  return { error: 'An error occurred' }; // Generic message\n"
                    "}"
                ),
                evidence={
                    "function": function.name,
                    "found_indicators": found_indicators,
                    "response_sample": self._truncate_response(function.response_sample),
                },
                cwe="CWE-209: Information Exposure Through an Error Message",
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                resource_type=ResourceType.FUNCTIONS,
            )
            findings.append(finding)

        return findings

    def _assess_function_severity(self, function: CloudFunction) -> Severity:
        """
        Assess the severity of an unauthenticated function based on its name and behavior.

        Args:
            function: CloudFunction to assess

        Returns:
            Severity level
        """
        high_risk_keywords = [
            "delete",
            "remove",
            "update",
            "modify",
            "create",
            "payment",
            "charge",
            "admin",
            "user",
            "account",
            "sensitive",
        ]
        medium_risk_keywords = ["send", "email", "notify", "process"]
        low_risk_keywords = ["hello", "test", "ping", "health"]

        function_name_lower = function.name.lower()

        # Check for high-risk operations
        if any(keyword in function_name_lower for keyword in high_risk_keywords):
            return Severity.HIGH

        # Check for medium-risk operations
        if any(keyword in function_name_lower for keyword in medium_risk_keywords):
            return Severity.MEDIUM

        # Check for low-risk operations
        if any(keyword in function_name_lower for keyword in low_risk_keywords):
            return Severity.LOW

        # Default to medium if unknown
        return Severity.MEDIUM

    def _truncate_response(self, response: any, max_size: int = 200) -> any:
        """
        Truncate response for evidence reporting.

        Args:
            response: Response to truncate
            max_size: Maximum size in characters

        Returns:
            Truncated response
        """
        import json

        try:
            response_str = json.dumps(response)
            if len(response_str) > max_size:
                return response_str[:max_size] + "..."
            return response
        except Exception:
            return str(response)[:max_size]
