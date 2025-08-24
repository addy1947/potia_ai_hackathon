#!/usr/bin/env python3
"""
Dependency Security Agent - Main CLI Application
Automated dependency security and management using Portia AI
"""

import sys
import os
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.agents.dependency_agent import DependencySecurityAgent
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import yaml
import shutil

console = Console()


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load configuration from file"""
    try:
        with open(config_path, "r") as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        console.print(f"[red]Configuration file {config_path} not found![/red]")
        return {}


def display_scan_results(results: Dict[str, Any]):
    """Display scan results in a formatted table"""
    if not results:
        console.print("[red]No results to display[/red]")
        return

    # Create summary table
    table = Table(title="Dependency Security Scan Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    # Handle different result structures
    if results.get("final_output"):
        # Handle results with final_output structure
        output = results.get("final_output", {})
        if isinstance(output, dict):
            for key, value in output.items():
                table.add_row(str(key).replace("_", " ").title(), str(value))
    else:
        # Handle direct result structure from our agent
        for key, value in results.items():
            if key not in ["status", "error"]:  # Skip internal fields
                table.add_row(str(key).replace("_", " ").title(), str(value))

        # Add status information
        if results.get("status"):
            table.add_row("Status", results["status"])
        if results.get("error"):
            table.add_row("Error", results["error"])

    console.print(table)


def display_repositories_status(repositories: List[Dict[str, str]]):
    """Display monitored repositories status"""
    table = Table(title="Monitored Repositories")
    table.add_column("Owner", style="cyan")
    table.add_column("Repository", style="green")
    table.add_column("Branch", style="yellow")

    for repo in repositories:
        table.add_row(
            repo.get("owner", "unknown"),
            repo.get("repo", "unknown"),
            repo.get("branch", "main"),
        )

    console.print(table)


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Dependency Security Agent - Automated dependency security management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan --repo octocat/Hello-World
  python main.py update --repo octocat/Hello-World --branch main
  python main.py emergency --cve CVE-2024-1234
  python main.py scheduled-scan
  python main.py report --repos octocat/Hello-World,user/repo2
        """,
    )

    # Global arguments
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a repository for security issues"
    )
    scan_parser.add_argument(
        "--repo", required=True, help="Repository in format owner/name"
    )
    scan_parser.add_argument(
        "--branch", default="main", help="Branch to scan (default: main)"
    )

    # Update command
    update_parser = subparsers.add_parser(
        "update", help="Update dependencies in a repository"
    )
    update_parser.add_argument(
        "--repo", required=True, help="Repository in format owner/name"
    )
    update_parser.add_argument(
        "--branch", default="main", help="Branch to update (default: main)"
    )

    # Workflow command
    workflow_parser = subparsers.add_parser(
        "workflow",
        help="Execute complete dependency update workflow (clone, update, PR, deploy)",
    )
    workflow_parser.add_argument(
        "--repo", required=True, help="Repository in format owner/name"
    )
    workflow_parser.add_argument(
        "--branch", default="main", help="Branch to update (default: main)"
    )
    workflow_parser.add_argument(
        "--update-type",
        choices=["patch", "minor", "major"],
        default="patch",
        help="Type of updates to apply (default: patch)",
    )

    # Emergency response command
    emergency_parser = subparsers.add_parser(
        "emergency", help="Handle emergency CVE response"
    )
    emergency_parser.add_argument(
        "--cve", required=True, help="CVE identifier (e.g., CVE-2024-1234)"
    )

    # Scheduled scan command
    subparsers.add_parser(
        "scheduled-scan", help="Run scheduled scan for all monitored repositories"
    )

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument(
        "--repos", help="Comma-separated list of repositories (owner/name)"
    )
    report_parser.add_argument(
        "--format",
        choices=["console", "json", "csv"],
        default="console",
        help="Output format",
    )

    # Status command
    subparsers.add_parser(
        "status", help="Show current configuration and monitored repositories"
    )

    # Test command
    subparsers.add_parser("test", help="Test Gemini AI configuration")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Load configuration
    config = load_config(args.config)

    try:
        # Initialize agent
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Initializing Dependency Security Agent...", total=None
            )

            agent = DependencySecurityAgent(config_path=args.config)

            progress.update(task, description="Agent initialized successfully ✓")

        # Execute commands
        if args.command == "scan":
            console.print(
                Panel.fit(f"🔍 Scanning Repository: {args.repo}", style="blue")
            )

            owner, repo = args.repo.split("/", 1)
            local_folder = f"repo/{owner}_{repo}"
            if os.path.exists(local_folder):
                shutil.rmtree(local_folder)
            os.makedirs(local_folder, exist_ok=True)

            # Clone the repository into the local_folder before scanning
            clone_result = agent.tools.get_tool("github_tool").execute(
                action="clone_repository",
                repo_owner=owner,
                repo_name=repo,
                branch=args.branch,
                local_path=local_folder,
            )
            if not clone_result.get("success"):
                console.print(
                    f"[red]Failed to clone repository: {clone_result.get('error')}[/red]"
                )
                return

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Running security scan...", total=None)

                result = agent.analyze_repository(owner, repo, args.branch)

                progress.update(task, description="Scan completed ✓")

            if args.verbose:
                console.print("\n[bold]Detailed Results:[/bold]")
                console.print(json.dumps(result, indent=2))
            else:
                display_scan_results(result)

        elif args.command == "update":
            console.print(
                Panel.fit(f"📦 Updating Dependencies: {args.repo}", style="green")
            )

            owner, repo = args.repo.split("/", 1)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Updating dependencies...", total=None)

                result = agent.update_dependencies(owner, repo, args.branch)

                progress.update(task, description="Update completed ✓")

            if args.verbose:
                console.print("\n[bold]Detailed Results:[/bold]")
                console.print(json.dumps(result, indent=2))
            else:
                display_scan_results(result)

        elif args.command == "workflow":
            console.print(
                Panel.fit(
                    f"🚀 Executing Dependency Update Workflow: {args.repo}",
                    style="magenta",
                )
            )

            owner, repo = args.repo.split("/", 1)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Executing workflow...", total=None)

                result = agent.execute_dependency_update_workflow(
                    owner, repo, args.branch, args.update_type
                )

                progress.update(task, description="Workflow completed ✓")

            if args.verbose:
                console.print("\n[bold]Detailed Results:[/bold]")
                console.print(json.dumps(result, indent=2))
            else:
                display_scan_results(result)

        elif args.command == "emergency":
            console.print(Panel.fit(f"🚨 Emergency Response: {args.cve}", style="red"))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Executing emergency response...", total=None)

                result = agent.emergency_response(args.cve)

                progress.update(task, description="Emergency response completed ✓")

            console.print("\n[bold]Emergency Response Results:[/bold]")
            console.print(json.dumps(result, indent=2))

        elif args.command == "scheduled-scan":
            console.print(
                Panel.fit("⏰ Running Scheduled Security Scan", style="yellow")
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Running scheduled scan...", total=None)

                result = agent.run_scheduled_scan()

                progress.update(task, description="Scheduled scan completed ✓")

            display_scan_results(result)

        elif args.command == "report":
            console.print(Panel.fit("📊 Generating Security Report", style="cyan"))

            # Parse repositories
            if args.repos:
                repo_list = []
                for repo_str in args.repos.split(","):
                    repo_str = repo_str.strip()
                    if "/" in repo_str:
                        owner, repo = repo_str.split("/", 1)
                        repo_list.append({"owner": owner, "repo": repo})
                    else:
                        console.print(
                            f"[red]Invalid repository format: {repo_str}[/red]"
                        )
                        continue
            else:
                # Use repositories from config
                repo_list = config.get("repositories", {}).get("monitored", [])

            if not repo_list:
                console.print("[red]No repositories specified for report[/red]")
                return

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Generating report...", total=None)

                result = agent.generate_security_report(repo_list)

                progress.update(task, description="Report generated ✓")

            if args.format == "json":
                console.print(json.dumps(result, indent=2))
            elif args.format == "csv":
                # This would need additional formatting logic
                console.print("CSV format not yet implemented")
            else:
                display_scan_results(result)

        elif args.command == "status":
            console.print(
                Panel.fit("📋 Dependency Security Agent Status", style="blue")
            )

            # Display configuration summary
            console.print("\n[bold]Configuration:[/bold]")

            policies = config.get("policies", {})
            version_policy = policies.get("version_updates", {})
            security_policy = policies.get("security", {})

            config_table = Table()
            config_table.add_column("Setting", style="cyan")
            config_table.add_column("Value", style="green")

            config_table.add_row(
                "Allow Major Updates",
                str(version_policy.get("allow_major_versions", False)),
            )
            config_table.add_row(
                "Allow Minor Updates",
                str(version_policy.get("allow_minor_versions", True)),
            )
            config_table.add_row(
                "Allow Patch Updates",
                str(version_policy.get("allow_patch_versions", True)),
            )
            config_table.add_row(
                "Max CVSS Score", str(security_policy.get("max_cvss_score", 7.0))
            )
            config_table.add_row(
                "Auto-fix Low Severity",
                str(security_policy.get("auto_fix_low_severity", True)),
            )

            console.print(config_table)

            # Display monitored repositories
            repositories = config.get("repositories", {}).get("monitored", [])
            if repositories:
                console.print("\n[bold]Monitored Repositories:[/bold]")
                display_repositories_status(repositories)
            else:
                console.print(
                    "\n[yellow]No repositories configured for monitoring[/yellow]"
                )

        elif args.command == "test":
            console.print(
                Panel.fit("🧪 Testing Gemini AI Configuration", style="green")
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Testing Gemini configuration...", total=None)

                # Test with a simple math question
                result = agent.gemini_client.run("What is 1 + 2?")

                progress.update(task, description="Configuration test completed ✓")

            if result["state"] == "COMPLETE":
                console.print("[green]✓ Gemini AI is working correctly![/green]")
                console.print(f"Test result: {result['final_output']['response']}")
            else:
                console.print("[red]✗ Gemini AI test failed[/red]")
                console.print(f"State: {result['state']}")
                if result.get("error"):
                    console.print(f"Error: {result['error']}")

        else:
            parser.print_help()

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if args.verbose:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
