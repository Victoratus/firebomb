"""
Terminal output formatting using Rich.
"""

from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from firebomb.models import (
    SecurityFinding,
    EnumerationResult,
    FirebaseConfig,
    Severity,
)


class OutputFormatter:
    """Formats output for terminal display using Rich."""

    def __init__(self):
        self.console = Console()

    def print_banner(self):
        """Print Firebomb banner."""
        banner = """
[bold red]    ______ _          _                     _
   |  ____(_)        | |                   | |
   | |__   _ _ __ ___| |__   ___  _ __ ___ | |__
   |  __| | | '__/ _ \\ '_ \\ / _ \\| '_ ` _ \\| '_ \\
   | |    | | | |  __/ |_) | (_) | | | | | | |_) |
   |_|    |_|_|  \\___|_.__/ \\___/|_| |_| |_|_.__/ [/bold red]

[bold cyan]Firebase Security Testing Tool[/bold cyan]
[dim]Comprehensive security assessment for Firebase projects[/dim]
"""
        self.console.print(banner)

    def print_config(self, config: FirebaseConfig):
        """
        Print Firebase configuration.

        Args:
            config: FirebaseConfig to display
        """
        table = Table(title="Firebase Configuration", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Project ID", config.project_id)
        table.add_row("API Key", f"{config.api_key[:20]}..." if len(config.api_key) > 20 else config.api_key)
        if config.auth_domain:
            table.add_row("Auth Domain", config.auth_domain)
        if config.database_url:
            table.add_row("Database URL", config.database_url)
        if config.storage_bucket:
            table.add_row("Storage Bucket", config.storage_bucket)
        if config.source_url:
            table.add_row("Source", config.source_url)

        self.console.print(table)

    def print_enumeration_result(self, result: EnumerationResult):
        """
        Print enumeration results in a tree structure.

        Args:
            result: EnumerationResult to display
        """
        self.console.print("\n[bold cyan]📊 Firebase Resources[/bold cyan]\n")

        # Firestore Collections
        if result.firestore_collections:
            firestore_tree = Tree("[bold]Firestore Collections[/bold]")
            for collection in result.firestore_collections:
                status = "⚠️  Accessible" if collection.readable_anon else "✓ Protected"
                color = "red" if collection.readable_anon else "green"
                firestore_tree.add(
                    f"[{color}]{collection.name}[/{color}] ({collection.document_count} docs) {status}"
                )
            self.console.print(firestore_tree)

        # Realtime Database
        if result.rtdb_paths:
            rtdb_tree = Tree("[bold]Realtime Database[/bold]")
            for path in result.rtdb_paths:
                status = "⚠️  Readable" if path.readable else "✓ Protected"
                color = "red" if path.readable else "green"
                rtdb_tree.add(f"[{color}]{path.path}[/{color}] {status}")
            self.console.print(rtdb_tree)

        # Cloud Storage
        if result.storage_buckets:
            storage_tree = Tree("[bold]Cloud Storage[/bold]")
            for bucket in result.storage_buckets:
                status = "⚠️  Public" if bucket.public_read else "✓ Protected"
                color = "red" if bucket.public_read else "green"
                storage_tree.add(
                    f"[{color}]{bucket.name}[/{color}] ({bucket.files_count} files) {status}"
                )
            self.console.print(storage_tree)

        # Cloud Functions
        if result.cloud_functions:
            functions_tree = Tree("[bold]Cloud Functions[/bold]")
            for function in result.cloud_functions:
                status = "⚠️  No auth required" if not function.requires_auth else "✓ Requires JWT"
                color = "red" if not function.requires_auth else "green"
                functions_tree.add(f"[{color}]{function.name}[/{color}] {status}")
            self.console.print(functions_tree)

        # Authentication
        if result.auth_config:
            auth_tree = Tree("[bold]Authentication[/bold]")
            config = result.auth_config

            if config.email_password_enabled:
                auth_tree.add("[green]✓ Email/Password Enabled[/green]")
            if config.google_oauth_enabled:
                auth_tree.add("[green]✓ Google OAuth Enabled[/green]")
            if config.anonymous_enabled:
                auth_tree.add("[yellow]⚠️  Anonymous Enabled[/yellow]")

            self.console.print(auth_tree)

    def print_findings(self, findings: List[SecurityFinding], summary: Dict[str, Any]):
        """
        Print security findings.

        Args:
            findings: List of SecurityFinding objects
            summary: Summary dictionary
        """
        # Print summary
        self.console.print(f"\n[bold cyan]🔍 Security Findings Summary[/bold cyan]\n")

        summary_table = Table(box=box.ROUNDED)
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")

        summary_table.add_row("[bold red]Critical[/bold red]", str(summary["critical"]))
        summary_table.add_row("[red]High[/red]", str(summary["high"]))
        summary_table.add_row("[yellow]Medium[/yellow]", str(summary["medium"]))
        summary_table.add_row("[blue]Low[/blue]", str(summary["low"]))
        summary_table.add_row("[dim]Info[/dim]", str(summary["info"]))
        summary_table.add_row("[bold]Total[/bold]", str(summary["total_findings"]))

        self.console.print(summary_table)

        # Print detailed findings
        if findings:
            self.console.print(f"\n[bold cyan]📋 Detailed Findings[/bold cyan]\n")

            for i, finding in enumerate(findings, 1):
                self._print_finding(finding, i)

    def _print_finding(self, finding: SecurityFinding, index: int):
        """
        Print a single security finding.

        Args:
            finding: SecurityFinding to display
            index: Finding number
        """
        # Determine color based on severity
        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        color = severity_colors.get(finding.severity.value, "white")

        # Create panel content
        content = f"[bold]Description:[/bold]\n{finding.description}\n\n"
        content += f"[bold]Affected Resource:[/bold]\n{finding.affected_resource}\n\n"
        content += f"[bold]Recommendation:[/bold]\n{finding.recommendation}"

        if finding.cwe:
            content += f"\n\n[dim]CWE: {finding.cwe}[/dim]"
        if finding.owasp:
            content += f"\n[dim]OWASP: {finding.owasp}[/dim]"

        # Create panel
        panel = Panel(
            content,
            title=f"[{color}]#{index} [{finding.severity.value.upper()}] {finding.title}[/{color}]",
            border_style=color,
            box=box.ROUNDED,
        )

        self.console.print(panel)
        self.console.print()  # Add spacing

    def print_success(self, message: str):
        """
        Print success message.

        Args:
            message: Message to display
        """
        self.console.print(f"[green]✓[/green] {message}")

    def print_error(self, message: str):
        """
        Print error message.

        Args:
            message: Message to display
        """
        self.console.print(f"[red]✗[/red] {message}")

    def print_warning(self, message: str):
        """
        Print warning message.

        Args:
            message: Message to display
        """
        self.console.print(f"[yellow]⚠[/yellow] {message}")

    def print_info(self, message: str):
        """
        Print info message.

        Args:
            message: Message to display
        """
        self.console.print(f"[cyan]ℹ[/cyan] {message}")

    def create_progress(self, description: str) -> Progress:
        """
        Create a progress spinner.

        Args:
            description: Description text

        Returns:
            Progress instance
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        )

    def print_cached_configs(self, configs: List[FirebaseConfig]):
        """
        Print cached configurations.

        Args:
            configs: List of FirebaseConfig objects
        """
        if not configs:
            self.console.print("[dim]No cached configurations found.[/dim]")
            return

        table = Table(title="Cached Firebase Configurations", box=box.ROUNDED)
        table.add_column("Project ID", style="cyan")
        table.add_column("API Key", style="white")
        table.add_column("Database URL", style="dim")
        table.add_column("Discovered", style="dim")

        for config in configs:
            api_key_short = f"{config.api_key[:15]}..." if len(config.api_key) > 15 else config.api_key
            db_url_short = (
                config.database_url[:30] + "..." if config.database_url and len(config.database_url) > 30 else (config.database_url or "N/A")
            )
            discovered = config.discovered_at.strftime("%Y-%m-%d %H:%M")

            table.add_row(config.project_id, api_key_short, db_url_short, discovered)

        self.console.print(table)
