"""Pentest Automation CLI Tool.

Command-line interface for managing pentest scans, reports, and system status.
"""

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID

import click
import httpx
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.style import Style
from rich.table import Table

from cli.config import get_api_base, load_config, save_config
from cli.utils import format_datetime, format_duration, get_severity_style

console = Console()


# Main CLI group
@click.group()
@click.version_option(version="1.0.0", prog_name="pentest-cli")
@click.option(
    "--api-url",
    envvar="PENTEST_API_URL",
    help="API base URL (default: http://localhost:8000/api)",
)
@click.pass_context
def cli(ctx, api_url):
    """Automated Penetration Testing Platform CLI.

    Manage scans, generate reports, and monitor system status.
    """
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url or get_api_base()


# Scan commands
@cli.group()
def scan():
    """Manage penetration testing scans."""
    pass


@scan.command("start")
@click.argument("name")
@click.option("--config", "-c", type=click.Path(exists=True), help="Pipeline config file (JSON/YAML)")
@click.option("--targets-file", "-t", type=click.Path(exists=True), help="File containing targets")
@click.option("--targets", multiple=True, help="Individual targets (can specify multiple)")
@click.option("--ftp-url", help="FTP URL to fetch targets from")
@click.pass_context
def scan_start(ctx, name, config, targets_file, targets, ftp_url):
    """Start a new scan.

    Examples:
        pentest-cli scan start "Web App Test" --config config.json --targets example.com
        pentest-cli scan start "Network Scan" --ftp-url ftp://server/targets.txt
    """
    try:
        api_url = ctx.obj["api_url"]

        # Load pipeline config
        pipeline_config = {}
        if config:
            import json
            import yaml

            config_path = Path(config)
            if config_path.suffix == ".json":
                pipeline_config = json.loads(config_path.read_text())
            elif config_path.suffix in [".yaml", ".yml"]:
                pipeline_config = yaml.safe_load(config_path.read_text())
        else:
            # Default config
            pipeline_config = {
                "stages": ["reconnaissance", "scanning", "exploitation"],
                "scanners": ["nmap", "nuclei"],
                "timeout": 3600,
            }

        # Prepare scan creation data
        scan_data = {
            "name": name,
            "pipeline_config": pipeline_config,
        }

        with console.status("[bold green]Creating scan..."):
            # Create scan
            response = httpx.post(f"{api_url}/scans", json=scan_data, timeout=30.0)
            response.raise_for_status()
            scan = response.json()
            scan_id = scan["id"]

        console.print(f"[green]✓[/green] Scan created: {scan['name']} (ID: {scan_id})")

        # Upload targets if provided
        if targets_file or targets or ftp_url:
            with console.status("[bold green]Uploading targets..."):
                # Prepare targets list
                targets_list = []

                if targets_file:
                    targets_list.extend(Path(targets_file).read_text().strip().split("\n"))

                if targets:
                    targets_list.extend(targets)

                # Upload targets
                upload_data = {"targets": targets_list}
                if ftp_url:
                    upload_data["ftp_url"] = ftp_url

                response = httpx.post(
                    f"{api_url}/targets/upload",
                    json=upload_data,
                    params={"scan_id": scan_id},
                    timeout=60.0,
                )
                response.raise_for_status()
                upload_result = response.json()

            console.print(f"[green]✓[/green] Uploaded {upload_result['targets_added']} targets")

        # Start scan
        with console.status("[bold green]Starting scan execution..."):
            response = httpx.post(f"{api_url}/scans/{scan_id}/start", timeout=30.0)
            response.raise_for_status()
            result = response.json()

        console.print(f"[green]✓[/green] Scan started successfully")
        console.print(f"\nCelery Task ID: {result['celery_task_id']}")
        console.print(f"\nMonitor progress: [cyan]pentest-cli scan status {scan_id} --follow[/cyan]")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@scan.command("status")
@click.argument("scan_id", type=str)
@click.option("--follow", "-f", is_flag=True, help="Follow scan progress in real-time")
@click.pass_context
def scan_status(ctx, scan_id, follow):
    """Get scan status and progress.

    Examples:
        pentest-cli scan status abc-123-def
        pentest-cli scan status abc-123-def --follow
    """
    try:
        api_url = ctx.obj["api_url"]

        if follow:
            # Real-time following with Live updates
            with Live(console=console, refresh_per_second=2) as live:
                while True:
                    try:
                        response = httpx.get(f"{api_url}/scans/{scan_id}/status", timeout=30.0)
                        response.raise_for_status()
                        status = response.json()

                        # Create status table
                        table = Table(title=f"Scan Status: {status['scan_name']}", show_header=False)
                        table.add_column("Property", style="cyan")
                        table.add_column("Value", style="white")

                        # Add rows
                        table.add_row("ID", str(status["scan_id"]))
                        table.add_row("Status", f"[bold]{status['status'].upper()}[/bold]")
                        table.add_row("Progress", f"{status['progress']}%")
                        table.add_row("Targets", f"{status['targets_completed']}/{status['targets_total']}")
                        table.add_row("Findings", str(status["findings_count"]))

                        if status.get("current_stage"):
                            table.add_row("Current Stage", status["current_stage"])

                        if status.get("started_at"):
                            table.add_row("Started At", format_datetime(status["started_at"]))

                        if status.get("completed_at"):
                            table.add_row("Completed At", format_datetime(status["completed_at"]))
                        elif status.get("started_at"):
                            elapsed = (datetime.utcnow() - datetime.fromisoformat(status["started_at"].replace("Z", "+00:00"))).total_seconds()
                            table.add_row("Elapsed", format_duration(int(elapsed)))

                        # Show errors if any
                        if status.get("errors"):
                            table.add_row("Errors", f"[red]{len(status['errors'])}[/red]")

                        live.update(table)

                        # Break if scan is completed or failed
                        if status["status"] in ["completed", "failed", "stopped"]:
                            break

                        time.sleep(2)

                    except httpx.HTTPError as e:
                        live.update(f"[red]Error fetching status: {e}[/red]")
                        time.sleep(5)
        else:
            # Single status check
            response = httpx.get(f"{api_url}/scans/{scan_id}/status", timeout=30.0)
            response.raise_for_status()
            status = response.json()

            # Create status table
            table = Table(title=f"Scan Status: {status['scan_name']}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("ID", str(status["scan_id"]))
            table.add_row("Status", f"[bold]{status['status'].upper()}[/bold]")
            table.add_row("Progress", f"{status['progress']}%")
            table.add_row("Targets", f"{status['targets_completed']}/{status['targets_total']}")
            table.add_row("Findings", str(status["findings_count"]))

            if status.get("current_stage"):
                table.add_row("Current Stage", status["current_stage"])

            if status.get("started_at"):
                table.add_row("Started At", format_datetime(status["started_at"]))

            if status.get("completed_at"):
                table.add_row("Completed At", format_datetime(status["completed_at"]))

            console.print(table)

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@scan.command("list")
@click.option("--status", type=click.Choice(["pending", "running", "completed", "failed", "paused"]), help="Filter by status")
@click.option("--limit", type=int, default=20, help="Maximum number of scans to display")
@click.pass_context
def scan_list(ctx, status, limit):
    """List all scans.

    Examples:
        pentest-cli scan list
        pentest-cli scan list --status running
        pentest-cli scan list --limit 50
    """
    try:
        api_url = ctx.obj["api_url"]

        params = {"limit": limit}
        if status:
            params["status"] = status

        with console.status("[bold green]Fetching scans..."):
            response = httpx.get(f"{api_url}/scans", params=params, timeout=30.0)
            response.raise_for_status()
            scans = response.json()

        if not scans:
            console.print("[yellow]No scans found[/yellow]")
            return

        # Create table
        table = Table(title=f"Scans ({len(scans)})")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Status", style="white")
        table.add_column("Progress", justify="right")
        table.add_column("Targets", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Created", style="dim")

        for s in scans:
            # Format status with color
            status_style = {
                "pending": "yellow",
                "running": "blue",
                "completed": "green",
                "failed": "red",
                "paused": "magenta",
            }.get(s["status"], "white")

            table.add_row(
                str(s["id"])[:8] + "...",
                s["name"],
                f"[{status_style}]{s['status'].upper()}[/{status_style}]",
                f"{s.get('progress', 0)}%",
                str(s.get("targets_count", 0)),
                str(s.get("findings_count", 0)),
                format_datetime(s["created_at"]),
            )

        console.print(table)

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@scan.command("stop")
@click.argument("scan_id", type=str)
@click.pass_context
def scan_stop(ctx, scan_id):
    """Stop a running scan.

    Examples:
        pentest-cli scan stop abc-123-def
    """
    try:
        api_url = ctx.obj["api_url"]

        with console.status(f"[bold yellow]Stopping scan {scan_id}..."):
            response = httpx.post(f"{api_url}/scans/{scan_id}/stop", timeout=30.0)
            response.raise_for_status()
            result = response.json()

        console.print(f"[green]✓[/green] {result['message']}")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@scan.command("pause")
@click.argument("scan_id", type=str)
@click.pass_context
def scan_pause(ctx, scan_id):
    """Pause a running scan.

    Examples:
        pentest-cli scan pause abc-123-def
    """
    try:
        api_url = ctx.obj["api_url"]

        with console.status(f"[bold yellow]Pausing scan {scan_id}..."):
            response = httpx.post(f"{api_url}/scans/{scan_id}/pause", timeout=30.0)
            response.raise_for_status()
            result = response.json()

        console.print(f"[green]✓[/green] {result['message']}")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@scan.command("resume")
@click.argument("scan_id", type=str)
@click.pass_context
def scan_resume(ctx, scan_id):
    """Resume a paused scan.

    Examples:
        pentest-cli scan resume abc-123-def
    """
    try:
        api_url = ctx.obj["api_url"]

        with console.status(f"[bold green]Resuming scan {scan_id}..."):
            response = httpx.post(f"{api_url}/scans/{scan_id}/resume", timeout=30.0)
            response.raise_for_status()
            result = response.json()

        console.print(f"[green]✓[/green] {result['message']}")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


# Report commands
@cli.group()
def report():
    """Generate and manage reports."""
    pass


@report.command("generate")
@click.argument("scan_id", type=str)
@click.option(
    "--type",
    "-t",
    type=click.Choice(["technical", "executive", "both"]),
    default="both",
    help="Report type to generate",
)
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.pass_context
def report_generate(ctx, scan_id, type, output):
    """Generate report for a scan.

    Examples:
        pentest-cli report generate abc-123-def
        pentest-cli report generate abc-123-def --type technical -o ./reports
    """
    try:
        api_url = ctx.obj["api_url"]
        output_dir = Path(output) if output else Path.cwd() / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)

        types_to_generate = []
        if type in ["technical", "both"]:
            types_to_generate.append("technical")
        if type in ["executive", "both"]:
            types_to_generate.append("executive")

        for report_type in types_to_generate:
            with console.status(f"[bold green]Generating {report_type} report..."):
                response = httpx.get(
                    f"{api_url}/reports/scans/{scan_id}/{report_type}",
                    timeout=120.0,
                    follow_redirects=True,
                )
                response.raise_for_status()

                # Save report
                filename = f"scan_{scan_id[:8]}_{report_type}.pdf"
                filepath = output_dir / filename
                filepath.write_bytes(response.content)

            console.print(f"[green]✓[/green] Generated {report_type} report: {filepath}")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@report.command("send")
@click.argument("scan_id", type=str)
@click.option("--telegram", help="Telegram chat ID")
@click.option("--email", help="Email address")
@click.option("--ftp", help="FTP URL for upload")
@click.pass_context
def report_send(ctx, scan_id, telegram, email, ftp):
    """Send report to specified destinations.

    Examples:
        pentest-cli report send abc-123-def --telegram 123456789
        pentest-cli report send abc-123-def --email admin@example.com
    """
    try:
        api_url = ctx.obj["api_url"]

        destinations = []

        if telegram:
            destinations.append({"method": "telegram", "config": {"chat_id": telegram}})

        if email:
            destinations.append({"method": "email", "config": {"to": email}})

        if ftp:
            destinations.append({"method": "ftp", "config": {"url": ftp}})

        if not destinations:
            console.print("[yellow]No destinations specified. Use --telegram, --email, or --ftp[/yellow]")
            return

        send_data = {
            "report_type": "technical",
            "destinations": destinations,
        }

        with console.status(f"[bold green]Sending report to {len(destinations)} destination(s)..."):
            response = httpx.post(
                f"{api_url}/reports/scans/{scan_id}/send",
                json=send_data,
                timeout=120.0,
            )
            response.raise_for_status()
            result = response.json()

        if result["success"]:
            console.print(f"[green]✓[/green] Report sent to {result['destinations_sent']} destination(s)")
        else:
            console.print(f"[yellow]⚠[/yellow] Partial success: {result['destinations_sent']} sent")

        if result.get("errors"):
            console.print("[red]Errors:[/red]")
            for error in result["errors"]:
                console.print(f"  - {error}")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


# System commands
@cli.group()
def system():
    """System status and management."""
    pass


@system.command("status")
@click.pass_context
def system_status(ctx):
    """Check system health and readiness.

    Examples:
        pentest-cli system status
    """
    try:
        api_url = ctx.obj["api_url"]

        with console.status("[bold green]Checking system status..."):
            # Get readiness
            response = httpx.get(f"{api_url}/readiness", timeout=10.0)
            response.raise_for_status()
            readiness = response.json()

        # Create status table
        table = Table(title="System Status")
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Latency", justify="right")

        # Overall status
        overall_style = "green" if readiness["ready"] else "red"
        overall_status = "READY" if readiness["ready"] else "NOT READY"

        # Add services
        for service_name, service_data in readiness["services"].items():
            status_text = "[green]UP[/green]" if service_data["available"] else "[red]DOWN[/red]"
            latency = f"{service_data.get('latency_ms', 0):.2f}ms" if service_data.get("latency_ms") else "N/A"

            table.add_row(service_name.upper(), status_text, latency)

        console.print(table)
        console.print(f"\nOverall Status: [{overall_style}]{overall_status}[/{overall_style}]")

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@system.command("metrics")
@click.pass_context
def system_metrics(ctx):
    """Show system metrics and statistics.

    Examples:
        pentest-cli system metrics
    """
    try:
        api_url = ctx.obj["api_url"]

        with console.status("[bold green]Fetching metrics..."):
            response = httpx.get(f"{api_url}/metrics", timeout=10.0)
            response.raise_for_status()
            metrics = response.json()

        # Create metrics table
        table = Table(title="System Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="white")

        # Add metrics
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                table.add_row(key.replace("_", " ").title(), str(value))
            elif isinstance(value, dict):
                # Nested metrics
                for sub_key, sub_value in value.items():
                    table.add_row(
                        f"{key.replace('_', ' ').title()} - {sub_key.replace('_', ' ').title()}",
                        str(sub_value),
                    )

        console.print(table)

    except httpx.HTTPError as e:
        console.print(f"[red]✗[/red] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


# Config commands
@cli.group()
def config():
    """Manage CLI configuration."""
    pass


@config.command("show")
def config_show():
    """Show current configuration."""
    try:
        cfg = load_config()

        table = Table(title="CLI Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")

        for key, value in cfg.items():
            table.add_row(key, str(value))

        console.print(table)

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set configuration value.

    Examples:
        pentest-cli config set api_url http://localhost:8000/api
    """
    try:
        cfg = load_config()
        cfg[key] = value
        save_config(cfg)

        console.print(f"[green]✓[/green] Set {key} = {value}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


# Interactive mode command
@cli.command("interactive")
@click.pass_context
def interactive_mode(ctx):
    """Start interactive shell mode.

    Provides a REPL-like interface with:
    - Command history
    - Auto-completion
    - Auto-suggestions from history

    Examples:
        pentest-cli interactive
    """
    try:
        from cli.interactive import run_interactive_mode

        run_interactive_mode(ctx.obj)

    except ImportError:
        console.print("[red]✗[/red] Interactive mode requires prompt_toolkit.")
        console.print("Install it with: pip install prompt-toolkit")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli(obj={})
