import click
from rich.console import Console

from threatforge.analyzer.entropy import calc_entropy
from threatforge.analyzer.fileinfo import get_file_info
from threatforge.analyzer.filetype import detect_file_type
from threatforge.analyzer.hashing import calc_hashes
from threatforge.analyzer.strings import extract_strings
from threatforge.analyzer.executable.detector import detect_executable_format
from threatforge.analyzer.executable.pe import analyze_pe
from threatforge.analyzer.executable.elf import analyze_elf
from threatforge.core.result import AnalysisResult
from threatforge.detector.rules import scan_entropy, scan_strings
from threatforge.detector.scoring import calc_risk
from threatforge.generator.samples import generate_test_sample
from threatforge.reporting.json_report import save_json_report
from threatforge.reporting.terminal import print_report

console = Console()

@click.group()
@click.version_option(version="0.3.0-beta", prog_name="Sec-n-ThreatForge")
def cli():
    """Sec-n-ThreatForge security research framework."""
    pass

@cli.command()
def info():
    """Display framework information."""
    console.print()
    console.print("[bold]Sec-n-ThreatForge[/bold]")
    console.print("Security, Threat Generation & Malware Analysis Framework")
    console.print("Version: 0.3.0-beta")
    console.print()

@cli.command()
@click.argument("path")
@click.option("--json", "json_output", help="Save analysis as JSON.")
def analyze(path, json_output):
    """Perform static analysis on a file."""

    try:
        file_info = get_file_info(path)
        hashes = calc_hashes(path)
        file_type = detect_file_type(path)
        entropy = calc_entropy(path)
        strings = extract_strings(path)

        exec_format = detect_executable_format(path)
        if exec_format == "PE":
            executable = analyze_pe(path)
        elif exec_format == "ELF":
            executable = analyze_elf(path)

    except FileNotFoundError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise SystemExit(1)

    findings = []
    findings.extend(scan_strings(strings))
    findings.extend(scan_entropy(entropy))
    risk = calc_risk(findings)
    result = AnalysisResult(
        file=file_info,
        hashes=hashes,
        file_type=file_type,
        executable=executable,
        entropy=entropy,
        strings=strings,
        findings=findings,
        risk=risk,
    )

    print_report(result)

    if json_output:
        save_json_report(result, json_output)
        console.print(f"[green]JSON report saved:[/green] "f"{json_output}")

@cli.command()
@click.option("--type", "sample_type", type=click.Choice(["benign", "marker", "suspicious"]), required=True)
@click.option("--output", required=True )
def generate(sample_type, output):
    """Generate a controlled test sample."""

    try:
        path = generate_test_sample(output, sample_type)

    except ValueError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise SystemExit(1)

    console.print(f"[green]Generated:[/green] {path}")

def main():
    cli()

if __name__=="__main__":
    main()