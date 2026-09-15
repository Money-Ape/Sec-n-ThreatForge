import click
from rich.console import Console
from pathlib import Path

from threatforge.analyzer.entropy import calc_entropy
from threatforge.analyzer.fileinfo import get_file_info
from threatforge.analyzer.filetype import detect_file_type
from threatforge.analyzer.hashing import calc_hashes
from threatforge.analyzer.strings import extract_strings
from threatforge.analyzer.executable.detector import detect_executable_format
from threatforge.analyzer.executable.pe import analyze_pe
from threatforge.analyzer.executable.elf import analyze_elf
from threatforge.core.result import AnalysisResult
from threatforge.detector.rules import run_detection_rules
from threatforge.detector.scoring import calc_risk
from threatforge.generator.samples import generate_test_sample
from threatforge.reporting.json_report import save_json_report, save_evaluation_json_report
from threatforge.evaluation.corpus import load_corpus
from threatforge.evaluation.runner import run_corpus
from threatforge.evaluation.metrics import calculate_metrics
from threatforge.reporting.terminal import print_report, print_evaluation_report

console = Console()

@click.group()
@click.version_option(version="0.5.0", prog_name="Sec-n-ThreatForge")
def cli():
    """Sec-n-ThreatForge security research framework."""
    pass

@cli.command()
def info():
    """Display framework information."""
    console.print()
    console.print("[bold]Sec-n-ThreatForge[/bold]")
    console.print("Security, Threat Generation & Malware Analysis Framework")
    console.print("Version: 0.5.0")
    console.print()

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True, help="Save analysis as JSON.")
def analyze(path, json_output):
    """Perform static analysis on a file."""
    try:
        filename = Path(path).name
        with console.status(f"[bold cyan]Analyzing the mission: {path}...[/bold cyan]", spinner="line"):     # -------------------- Processing spinner
            try:
                file_info = get_file_info(path)
                hashes = calc_hashes(path)
                file_type = detect_file_type(path)
                entropy = calc_entropy(path)
                strings = extract_strings(path)

                executable = {}
                exec_format = detect_executable_format(path)
                if exec_format == "PE":
                    executable = analyze_pe(path)
                elif exec_format == "ELF":
                    executable = analyze_elf(path)

            except FileNotFoundError as error:
                console.print(f"[red]Error:[/red] {error}")
                raise SystemExit(1)

            result = AnalysisResult(
                file=file_info,
                hashes=hashes,
                file_type=file_type,
                executable=executable,
                entropy=entropy,
                strings=strings,
            )
            result.findings = run_detection_rules(result)
            result.risk = calc_risk(result.findings)

    except Exception as error:
        console.print(f"[bold red]Error:[/bold red] {error}")
        raise click.Abort()

    print_report(result)

    if json_output:
        save_json_report(result, json_output)
        console.print(f"[green]JSON report saved:[/green] "f"{json_output}")

@cli.command()
@click.option("--corpus", "corpus_path", default="corpus/manifest.json", show_default=True, help="Path to the evaluation corpus manifest.")
@click.option("--json", "json_output", type=click.Path(), help="Save evaluation results as JSON.")
def evaluate(corpus_path, json_output):
    # Evaluate the detection engine against a controlled corpus.
    try:
        samples = load_corpus(corpus_path)
        results = run_corpus(samples, root=".",)
        metrics = calculate_metrics(results)

    except FileNotFoundError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise SystemExit(1)

    print_evaluation_report(results, metrics)

    if json_output:
        save_evaluation_json_report(results, metrics, json_output)
        console.print(f"[green]JSON evaluation report saved:[/green] {json_output}")

@cli.command()
@click.option("--type", "sample_type",
    type=click.Choice([
        "benign",
        "marker",
        "suspicious",
        "marker-case",
        "marker-context",
        "marker-duplicate",
        "marker-spaced",
        "marker-mixed-case",
        "powershell-string",
        "cmd-string",
        "multiple-suspicious-strings"]), required=True,
)
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