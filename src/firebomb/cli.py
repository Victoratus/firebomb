"""
Command-line interface for Firebomb.
"""

import click
import sys
from pathlib import Path
import json

from firebomb import __version__
from firebomb.discovery import FirebaseDiscovery
from firebomb.testing import FirebaseTester
from firebomb.cache import CredentialCache
from firebomb.output_formatting import OutputFormatter
from firebomb.report_generator import ReportGenerator
from firebomb.models import FirebaseConfig


@click.group()
@click.version_option(version=__version__)
def cli():
    """
    Firebomb - Firebase Security Testing Tool

    Comprehensive security assessment for Firebase projects.
    """
    pass


@cli.command()
@click.option("--url", help="Target URL to discover Firebase config from")
@click.option("--file", "file_path", help="JavaScript file path to extract config from")
@click.option("--har", "har_path", help="HAR file path to extract config from")
@click.option("--deep", is_flag=True, help="Deep crawl to find config in linked JS files")
@click.option("--save", is_flag=True, help="Save discovered config to cache")
def discover(url, file_path, har_path, deep, save):
    """
    Discover Firebase configuration from web applications.

    Examples:
        firebomb discover --url https://example.com
        firebomb discover --file bundle.js
        firebomb discover --har network.har
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    discovery = FirebaseDiscovery()
    config = None

    try:
        if url:
            formatter.print_info(f"Discovering Firebase config from URL: {url}")
            config = discovery.discover_from_url(url, deep_crawl=deep)
        elif file_path:
            formatter.print_info(f"Discovering Firebase config from file: {file_path}")
            config = discovery.discover_from_js_file(file_path)
        elif har_path:
            formatter.print_info(f"Discovering Firebase config from HAR: {har_path}")
            config = discovery.discover_from_har(har_path)
        else:
            formatter.print_error("Please specify --url, --file, or --har")
            sys.exit(1)

        if config:
            formatter.print_success("Firebase configuration discovered!")
            formatter.print_config(config)

            # Validate the config
            if discovery.validate_config(config):
                formatter.print_success("Configuration validated successfully")
            else:
                formatter.print_warning("Configuration validation failed")

            # Save to cache if requested
            if save:
                cache = CredentialCache()
                cache.add(config)
                formatter.print_success(f"Configuration saved to cache: {config.project_id}")
        else:
            formatter.print_error("No Firebase configuration found")
            sys.exit(1)

    except Exception as e:
        formatter.print_error(f"Error during discovery: {str(e)}")
        sys.exit(1)


@cli.command()
@click.option("--project-id", help="Firebase project ID")
@click.option("--api-key", help="Firebase API key")
@click.option("--output", help="Output file path for JSON results")
def enum(project_id, api_key, output):
    """
    Enumerate Firebase resources (Firestore, RTDB, Storage, Functions).

    Examples:
        firebomb enum
        firebomb enum --project-id my-project --api-key AIza...
        firebomb enum --output results.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    # Get config from args or cache
    config = _get_config(project_id, api_key, formatter)
    if not config:
        sys.exit(1)

    try:
        # Initialize tester
        tester = FirebaseTester(config)

        # Enumerate resources
        with formatter.create_progress("Enumerating Firebase resources...") as progress:
            task = progress.add_task("Enumerating...", total=None)
            result = tester.enumerate()
            progress.update(task, completed=True)

        # Print results
        formatter.print_enumeration_result(result)

        # Save to JSON if requested
        if output:
            output_data = result.to_dict()
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)
            formatter.print_success(f"Results saved to: {output}")

    except Exception as e:
        formatter.print_error(f"Error during enumeration: {str(e)}")
        sys.exit(1)


@cli.command()
@click.option("--project-id", help="Firebase project ID")
@click.option("--api-key", help="Firebase API key")
@click.option("--firestore-only", is_flag=True, help="Test only Firestore")
@click.option("--storage-only", is_flag=True, help="Test only Cloud Storage")
@click.option("--functions-only", is_flag=True, help="Test only Cloud Functions")
@click.option("--output", help="Output file path for JSON results")
def test(project_id, api_key, firestore_only, storage_only, functions_only, output):
    """
    Run security tests on Firebase resources.

    Examples:
        firebomb test
        firebomb test --project-id my-project --api-key AIza...
        firebomb test --firestore-only
        firebomb test --output report.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    # Get config from args or cache
    config = _get_config(project_id, api_key, formatter)
    if not config:
        sys.exit(1)

    try:
        # Initialize tester
        tester = FirebaseTester(config)

        # Enumerate first
        formatter.print_info("Enumerating resources...")
        with formatter.create_progress("Enumerating...") as progress:
            task = progress.add_task("Scanning...", total=None)
            enumeration = tester.enumerate()
            progress.update(task, completed=True)

        # Run tests
        formatter.print_info("Running security tests...")
        with formatter.create_progress("Testing...") as progress:
            task = progress.add_task("Analyzing...", total=None)

            if firestore_only:
                findings = tester.test_firestore_only(enumeration)
            elif storage_only:
                findings = tester.test_storage_only(enumeration)
            elif functions_only:
                findings = tester.test_functions_only(enumeration)
            else:
                findings = tester.test_all(enumeration)

            progress.update(task, completed=True)

        # Get summary
        summary = tester.get_summary(findings)

        # Print results
        formatter.print_findings(findings, summary)

        # Save to JSON if requested
        if output:
            report_gen = ReportGenerator(config)
            if output.endswith(".html"):
                report_gen.generate_html(findings, summary, enumeration, output)
                formatter.print_success(f"HTML report saved to: {output}")
            else:
                report_gen.generate_json(findings, summary, enumeration, output)
                formatter.print_success(f"JSON report saved to: {output}")

    except Exception as e:
        formatter.print_error(f"Error during testing: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option("--project-id", help="Firebase project ID")
@click.option("--api-key", help="Firebase API key")
@click.option("--collection", help="Firestore collection name")
@click.option("--path", help="Realtime Database path")
@click.option("--limit", default=10, help="Number of documents/items to retrieve")
@click.option("--output", help="Output file path")
@click.option("--format", "output_format", type=click.Choice(["json", "csv"]), default="json", help="Output format")
def query(project_id, api_key, collection, path, limit, output, output_format):
    """
    Query Firestore collections or Realtime Database paths.

    Examples:
        firebomb query --collection users --limit 10
        firebomb query --path /users --output users.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    # Get config from args or cache
    config = _get_config(project_id, api_key, formatter)
    if not config:
        sys.exit(1)

    if not collection and not path:
        formatter.print_error("Please specify --collection or --path")
        sys.exit(1)

    try:
        from firebomb.client import FirebaseClient

        config_dict = {
            "project_id": config.project_id,
            "api_key": config.api_key,
            "database_url": config.database_url,
            "storage_bucket": config.storage_bucket,
        }
        client = FirebaseClient(config_dict)

        if collection:
            formatter.print_info(f"Querying Firestore collection: {collection}")
            docs, success = client.read_firestore_collection(collection, use_auth=False, limit=limit)

            if success and docs:
                formatter.print_success(f"Retrieved {len(docs)} documents")
                if output:
                    with open(output, "w") as f:
                        json.dump(docs, f, indent=2)
                    formatter.print_success(f"Results saved to: {output}")
                else:
                    print(json.dumps(docs, indent=2))
            else:
                formatter.print_warning("No documents found or access denied")

        elif path:
            formatter.print_info(f"Querying Realtime Database path: {path}")
            data, success = client.read_rtdb_path(path, use_auth=False)

            if success and data:
                formatter.print_success("Data retrieved")
                if output:
                    with open(output, "w") as f:
                        json.dump(data, f, indent=2)
                    formatter.print_success(f"Results saved to: {output}")
                else:
                    print(json.dumps(data, indent=2))
            else:
                formatter.print_warning("No data found or access denied")

    except Exception as e:
        formatter.print_error(f"Error during query: {str(e)}")
        sys.exit(1)


@cli.command()
@click.option("--project-id", help="Firebase project ID")
@click.option("--api-key", help="Firebase API key")
@click.option("--email", help="Email address for signup")
@click.option("--password", help="Password for signup")
def signup(project_id, api_key, email, password):
    """
    Create a test user account for authenticated testing.

    Examples:
        firebomb signup --email test@example.com --password Test123!
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    # Get config from args or cache
    config = _get_config(project_id, api_key, formatter)
    if not config:
        sys.exit(1)

    try:
        from firebomb.client import FirebaseClient

        config_dict = {
            "project_id": config.project_id,
            "api_key": config.api_key,
        }
        client = FirebaseClient(config_dict)

        if email and password:
            formatter.print_info(f"Creating user account: {email}")
            user_id, token, error = client.signup_email_password(email, password)

            if user_id and token:
                formatter.print_success(f"User created successfully!")
                formatter.print_info(f"User ID: {user_id}")
                formatter.print_info(f"ID Token: {token[:50]}...")
            else:
                formatter.print_error(f"Signup failed: {error}")
                sys.exit(1)
        else:
            # Try anonymous signup
            formatter.print_info("Creating anonymous user...")
            user_id, token = client.signup_anonymous()

            if user_id and token:
                formatter.print_success("Anonymous user created successfully!")
                formatter.print_info(f"User ID: {user_id}")
                formatter.print_info(f"ID Token: {token[:50]}...")
            else:
                formatter.print_error("Anonymous signup failed")
                sys.exit(1)

    except Exception as e:
        formatter.print_error(f"Error during signup: {str(e)}")
        sys.exit(1)


@cli.command()
@click.option("--remove", help="Remove cached config by project ID")
@click.option("--clear", is_flag=True, help="Clear all cached configs")
def cached(remove, clear):
    """
    Manage cached Firebase configurations.

    Examples:
        firebomb cached
        firebomb cached --remove my-project
        firebomb cached --clear
    """
    formatter = OutputFormatter()
    cache = CredentialCache()

    if clear:
        cache.clear()
        formatter.print_success("All cached configurations cleared")
        return

    if remove:
        if cache.remove(remove):
            formatter.print_success(f"Removed cached configuration: {remove}")
        else:
            formatter.print_error(f"Configuration not found: {remove}")
        return

    # List cached configs
    configs = cache.list()
    if configs:
        formatter.print_cached_configs(configs)
    else:
        formatter.print_info("No cached configurations found")


@cli.command()
@click.option("--project-id", help="Firebase project ID")
@click.option("--api-key", help="Firebase API key")
@click.option("--format", "output_format", type=click.Choice(["json", "html"]), default="html", help="Report format")
@click.option("--output", required=True, help="Output file path")
def report(project_id, api_key, output_format, output):
    """
    Generate a comprehensive security report.

    Examples:
        firebomb report --output report.html
        firebomb report --format json --output report.json
    """
    formatter = OutputFormatter()
    formatter.print_banner()

    # Get config from args or cache
    config = _get_config(project_id, api_key, formatter)
    if not config:
        sys.exit(1)

    try:
        # Initialize tester
        tester = FirebaseTester(config)

        # Enumerate
        formatter.print_info("Enumerating resources...")
        enumeration = tester.enumerate()

        # Test
        formatter.print_info("Running security tests...")
        findings = tester.test_all(enumeration)
        summary = tester.get_summary(findings)

        # Generate report
        report_gen = ReportGenerator(config)

        if output_format == "html":
            report_gen.generate_html(findings, summary, enumeration, output)
        else:
            report_gen.generate_json(findings, summary, enumeration, output)

        formatter.print_success(f"Report generated: {output}")

    except Exception as e:
        formatter.print_error(f"Error generating report: {str(e)}")
        sys.exit(1)


def _get_config(project_id, api_key, formatter) -> FirebaseConfig:
    """
    Get Firebase config from arguments or cache.

    Args:
        project_id: Optional project ID
        api_key: Optional API key
        formatter: OutputFormatter instance

    Returns:
        FirebaseConfig or None
    """
    if project_id and api_key:
        # Use provided credentials
        return FirebaseConfig(project_id=project_id, api_key=api_key)

    # Try to get from cache
    cache = CredentialCache()
    configs = cache.list()

    if not configs:
        formatter.print_error("No cached configurations found")
        formatter.print_info("Please provide --project-id and --api-key, or run 'firebomb discover' first")
        return None

    if len(configs) == 1:
        # Use the only cached config
        config = configs[0]
        formatter.print_info(f"Using cached configuration: {config.project_id}")
        return config

    if project_id:
        # Find specific project in cache
        config = cache.get(project_id)
        if config:
            formatter.print_info(f"Using cached configuration: {project_id}")
            return config
        else:
            formatter.print_error(f"Project not found in cache: {project_id}")
            return None

    # Multiple configs, need user to specify
    formatter.print_error("Multiple configurations found in cache")
    formatter.print_info("Please specify --project-id or run 'firebomb cached' to list them")
    return None


if __name__ == "__main__":
    cli()
