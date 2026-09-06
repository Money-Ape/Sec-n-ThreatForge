from rich.console import Console
from rich.table import Table
from threatforge.core.result import AnalysisResult

console = Console()

def print_report(result: AnalysisResult) -> None:

    table = Table(title="Sec-n-ThreatForge Analysis")

    table.add_column("Property")
    table.add_column("Value")

    table.add_row("Name", result.file["name"])
    table.add_row("Size", f'{result.file["size"]} bytes')
    table.add_row("Extension", result.file["extension"])
    table.add_row("MIME", result.file_type["mime"])
    table.add_row("Type", result.file_type["description"])

    if result.executable:
        table.add_row("Executable Format", result.executable.get("format", "Unknown"))
        table.add_row("Architecture", result.executable.get("architecture", "Unknown"))
        table.add_row("Entry Point", result.executable.get("entry_point", "Unknown"))

    table.add_row("SHA-256", result.hashes["sha256"])
    table.add_row("Entropy", str(result.entropy))
    table.add_row("Strings", str(len(result.strings)))
    table.add_row("Findings", str(len(result.findings)))
    table.add_row("Risk Score", str(result.risk["score"]))
    table.add_row("Classification", result.risk["classification"])

    console.print()
    console.print(table)
    console.print()

    if result.findings:

        console.print(
            "[bold]Findings[/bold]"
        )

        for finding in result.findings:

            console.print(
                f'  • '
                f'{finding.get("description")} '
                f'(severity: '
                f'{finding.get("severity")})'
            )