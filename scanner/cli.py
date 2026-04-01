"""CLI entry point for AI Compliance Scanner."""

import click
from rich.console import Console
from pathlib import Path

from .analyzer import Analyzer
from .reporter import Reporter

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="ai-compliance-scanner")
def cli():
    """AI Compliance Scanner — Check your AI project for EU AI Act & GDPR compliance."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--output", "-o", default="compliance_report.md", help="Output file for the report")
@click.option("--format", "-f", "fmt", default="rich", type=click.Choice(["rich", "json", "markdown"]), help="Report format")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed scan information")
def scan(path, output, fmt, verbose):
    """Scan a project directory for compliance issues.

    PATH is the directory to scan (defaults to current directory).
    """
    target = Path(path).resolve()
    console.print(f"\n[bold blue]AI Compliance Scanner v0.1.0[/bold blue] by DUGI")
    console.print(f"[dim]Scanning: {target}[/dim]\n")

    analyzer = Analyzer(target, verbose=verbose)
    results = analyzer.run()

    reporter = Reporter(results, target)
    reporter.render(fmt=fmt, output_file=output)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def quick(path):
    """Run a quick compliance check and print a summary."""
    target = Path(path).resolve()
    console.print(f"\n[bold blue]Quick Compliance Check[/bold blue] — {target.name}\n")

    analyzer = Analyzer(target, verbose=False)
    results = analyzer.run()

    reporter = Reporter(results, target)
    reporter.quick_summary()


@cli.command()
@click.option("--port", "-p", default=5050, help="Port to run the web UI on")
def ui(port):
    """Launch the web UI dashboard in your browser."""
    from .web.app import app
    import webbrowser
    import threading

    url = f"http://localhost:{port}"
    console.print(f"\n[bold blue]AI Compliance Scanner — Web UI[/bold blue]")
    console.print(f"[dim]Opening {url} ...[/dim]\n")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="0.0.0.0", port=port, debug=False)


def main():
    cli()


if __name__ == "__main__":
    main()
