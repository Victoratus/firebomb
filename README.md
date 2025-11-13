# 🔥 Firebomb

**Firebase Security Testing Tool** - Comprehensive CLI for Firebase security assessment and penetration testing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Overview

Firebomb is a powerful security testing tool designed to identify misconfigurations and vulnerabilities in Firebase applications. It automates the discovery, enumeration, and security testing of Firebase resources including Firestore, Realtime Database, Cloud Storage, Cloud Functions, and Authentication.

### Key Features

- 🔍 **Automatic Discovery** - Extract Firebase configurations from web applications, JavaScript bundles, or HAR files
- 📊 **Resource Enumeration** - Discover and list all accessible Firebase resources
- 🛡️ **Security Testing** - Comprehensive security tests for all Firebase services
- 📋 **Detailed Reporting** - Generate JSON and HTML reports with remediation guidance
- 💾 **Credential Caching** - Automatically cache discovered configurations for quick access
- 🎯 **Targeted Testing** - Test specific services (Firestore, Storage, Functions)
- 🎨 **Rich Terminal Output** - Beautiful, colored terminal output for easy reading

### What Firebomb Tests

#### Firestore Security Rules
- Public read/write access
- Missing authentication checks
- Sensitive data exposure
- Cross-user data access vulnerabilities

#### Realtime Database Rules
- Public database paths
- Wildcard permission issues
- Path traversal vulnerabilities
- Sensitive data in public paths

#### Cloud Storage
- Public bucket access (read/write)
- Exposed sensitive files
- Unauthorized file operations
- ACL misconfigurations

#### Cloud Functions
- Unauthenticated function access
- CORS misconfigurations
- Information disclosure
- Missing authentication checks

#### Authentication Configuration
- Anonymous auth enabled
- Email verification requirements
- Password policy strength
- Provider security settings

## Installation

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/Victoratus/firebomb.git
cd firebomb

# Install with uv
uv sync

# Run Firebomb
uv run firebomb --help
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/Victoratus/firebomb.git
cd firebomb

# Install dependencies
pip install -e .

# Run Firebomb
firebomb --help
```

## Quick Start

### 1. Discover Firebase Configuration

Extract Firebase configuration from a web application:

```bash
# From a URL
firebomb discover --url https://example.com --save

# From a JavaScript file
firebomb discover --file app-bundle.js --save

# From a HAR file (network traffic export)
firebomb discover --har network-capture.har --save

# Deep crawl with linked JS files
firebomb discover --url https://example.com --deep --save
```

The `--save` flag automatically caches the discovered configuration for future use.

### 2. Enumerate Resources

List all accessible Firebase resources:

```bash
# Using cached config
firebomb enum

# With explicit credentials
firebomb enum --project-id my-project --api-key AIza...

# Save results to JSON
firebomb enum --output enumeration.json
```

### 3. Run Security Tests

Perform comprehensive security testing:

```bash
# Test everything
firebomb test

# Test specific services
firebomb test --firestore-only
firebomb test --storage-only
firebomb test --functions-only

# Generate detailed report
firebomb test --output report.html
firebomb test --output report.json
```

### 4. Query Data

Extract data from accessible resources:

```bash
# Query Firestore collection
firebomb query --collection users --limit 10

# Query Realtime Database path
firebomb query --path /users --output users.json

# Export to CSV
firebomb query --collection orders --format csv --output orders.csv
```

### 5. Test with Authentication

Create a test user for authenticated testing:

```bash
# Create email/password user
firebomb signup --email test@example.com --password Test123!

# Create anonymous user
firebomb signup
```

Use the returned ID token for authenticated requests in other commands.

## Command Reference

### `firebomb discover`

Discover Firebase configurations from web applications.

**Options:**
- `--url URL` - Target web application URL
- `--file FILE` - JavaScript file to analyze
- `--har FILE` - HAR file from browser network capture
- `--deep` - Crawl linked JavaScript files
- `--save` - Save discovered config to cache

**Example:**
```bash
firebomb discover --url https://app.example.com --deep --save
```

### `firebomb enum`

Enumerate Firebase resources.

**Options:**
- `--project-id ID` - Firebase project ID (optional if cached)
- `--api-key KEY` - Firebase API key (optional if cached)
- `--output FILE` - Save results to JSON file

**Example:**
```bash
firebomb enum --output results.json
```

### `firebomb test`

Run security tests on Firebase resources.

**Options:**
- `--project-id ID` - Firebase project ID (optional if cached)
- `--api-key KEY` - Firebase API key (optional if cached)
- `--firestore-only` - Test only Firestore
- `--storage-only` - Test only Cloud Storage
- `--functions-only` - Test only Cloud Functions
- `--output FILE` - Generate report (JSON or HTML)

**Example:**
```bash
firebomb test --output report.html
```

### `firebomb query`

Query Firestore collections or Realtime Database paths.

**Options:**
- `--collection NAME` - Firestore collection name
- `--path PATH` - Realtime Database path
- `--limit N` - Maximum items to retrieve (default: 10)
- `--output FILE` - Save results to file
- `--format FORMAT` - Output format (json or csv)

**Example:**
```bash
firebomb query --collection users --limit 50 --output users.json
```

### `firebomb signup`

Create test user accounts for authenticated testing.

**Options:**
- `--email EMAIL` - Email address for signup
- `--password PASSWORD` - Password for signup
- `--project-id ID` - Firebase project ID (optional if cached)
- `--api-key KEY` - Firebase API key (optional if cached)

**Example:**
```bash
firebomb signup --email test@example.com --password SecurePass123!
```

### `firebomb cached`

Manage cached Firebase configurations.

**Options:**
- `--remove PROJECT_ID` - Remove specific cached config
- `--clear` - Clear all cached configs

**Example:**
```bash
# List all cached configs
firebomb cached

# Remove specific config
firebomb cached --remove my-project

# Clear all
firebomb cached --clear
```

### `firebomb report`

Generate comprehensive security reports.

**Options:**
- `--format FORMAT` - Report format (html or json)
- `--output FILE` - Output file path (required)
- `--project-id ID` - Firebase project ID (optional if cached)
- `--api-key KEY` - Firebase API key (optional if cached)

**Example:**
```bash
firebomb report --format html --output security-report.html
```

## Example Workflow

Here's a complete security assessment workflow:

```bash
# 1. Discover Firebase config from target application
firebomb discover --url https://target-app.com --deep --save

# 2. Enumerate all resources
firebomb enum --output enumeration.json

# 3. Run comprehensive security tests
firebomb test --output findings.json

# 4. Generate HTML report for stakeholders
firebomb report --format html --output security-assessment.html

# 5. Extract data from vulnerable collections
firebomb query --collection exposed-users --output leaked-data.json

# 6. Test with authenticated access
firebomb signup --email tester@example.com --password Test123!
firebomb test --output authenticated-findings.json
```

## Understanding the Output

### Security Findings

Firebomb categorizes findings by severity:

- **CRITICAL** 🔴 - Immediate action required (e.g., public write access)
- **HIGH** 🟠 - Significant security risk (e.g., public read access to sensitive data)
- **MEDIUM** 🟡 - Moderate risk (e.g., anonymous auth enabled)
- **LOW** 🔵 - Minor concern (e.g., weak password policy)
- **INFO** ⚪ - Informational (e.g., configuration summary)

Each finding includes:
- **Title** - Brief description
- **Description** - Detailed explanation of the issue
- **Affected Resource** - Specific resource or path
- **Recommendation** - Step-by-step remediation guidance
- **Evidence** - Technical details and samples
- **CWE/OWASP** - Industry-standard vulnerability classifications

### Sample Finding

```
#1 [HIGH] Firestore Collection "users" Publicly Readable

Description:
The Firestore collection 'users' allows anonymous read access. Anyone with
the Firebase API key can read 150 documents from this collection without
authentication.

Affected Resource:
Firestore Collection: users

Recommendation:
Add security rules to restrict read access to authenticated users only:
match /databases/{database}/documents/users/{document} {
  allow read: if request.auth != null;
}

CWE: CWE-284: Improper Access Control
OWASP: API1:2023 Broken Object Level Authorization
```

## Security Best Practices

After running Firebomb, follow these best practices:

### Firestore
1. Never use `allow read, write: if true;` in production
2. Always require authentication: `if request.auth != null`
3. Implement user-specific rules: `if request.auth.uid == resource.data.userId`
4. Use field-level security rules
5. Regularly audit security rules

### Realtime Database
1. Avoid `.read: true` and `.write: true` rules
2. Use authentication checks: `"auth != null"`
3. Implement user-based rules: `"auth.uid === $uid"`
4. Structure data to minimize public paths
5. Enable security rules logging

### Cloud Storage
1. Require authentication for all operations
2. Validate file types and sizes
3. Use user-specific paths: `/users/{userId}/files/{fileName}`
4. Implement metadata-based access control
5. Regularly review bucket ACLs

### Cloud Functions
1. Always validate authentication tokens
2. Implement proper authorization checks
3. Use Firebase Auth middleware
4. Configure CORS appropriately
5. Avoid exposing internal errors

### Authentication
1. Disable anonymous auth unless required
2. Require email verification
3. Enforce strong password policies (12+ characters)
4. Enable multi-factor authentication
5. Monitor failed authentication attempts

## Integration with CI/CD

Integrate Firebomb into your CI/CD pipeline:

```yaml
# GitHub Actions example
name: Firebase Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh

      - name: Install Firebomb
        run: |
          git clone https://github.com/Victoratus/firebomb.git
          cd firebomb && uv sync

      - name: Run security scan
        run: |
          cd firebomb
          uv run firebomb test --project-id ${{ secrets.FIREBASE_PROJECT_ID }} \
            --api-key ${{ secrets.FIREBASE_API_KEY }} \
            --output report.json

      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: firebomb/report.json
```

## Troubleshooting

### "No cached configurations found"

Run `firebomb discover` first to extract and cache Firebase configuration, or provide `--project-id` and `--api-key` explicitly.

### "Configuration validation failed"

The discovered API key or project ID may be invalid. Verify the configuration is correct.

### "Access denied" during enumeration

This is expected for properly secured resources. Firebomb will still test common patterns and report findings.

### Missing dependencies

Install required dependencies:
```bash
uv sync  # with uv
# or
pip install -e .  # with pip
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Victoratus/firebomb.git
cd firebomb

# Install development dependencies
uv sync

# Run tests
uv run pytest

# Format code
uv run black src/
uv run ruff check src/
```

## Legal Disclaimer

**IMPORTANT:** Firebomb is intended for security testing and research purposes only.

- ✅ **Authorized Testing**: Use on Firebase projects you own or have explicit permission to test
- ✅ **Security Research**: Responsible disclosure of vulnerabilities
- ✅ **Educational**: Learning about Firebase security
- ❌ **Unauthorized Access**: Never test systems without permission
- ❌ **Malicious Use**: Any harmful or illegal activities

Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this tool.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

Developed by [Víctor Yrazusta](https://github.com/Victoratus) as part of [TheCyberAgents](https://thecyberagents.com) project.

Inspired by the need for comprehensive Firebase security testing tools and built with insights from:
- Firebase Security Documentation
- OWASP API Security Top 10
- Real-world Firebase security incidents

## Resources

- [Firebase Security Rules Documentation](https://firebase.google.com/docs/rules)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [CWE Database](https://cwe.mitre.org/)
- [Firebase Security Best Practices](https://firebase.google.com/docs/rules/basics)

## Support

- 🐛 [Report Issues](https://github.com/Victoratus/firebomb/issues)
- 💬 [Discussions](https://github.com/Victoratus/firebomb/discussions)
- 📧 Contact: victor@thecyberagents.com

---

**Happy (Ethical) Hacking! 🔥**
