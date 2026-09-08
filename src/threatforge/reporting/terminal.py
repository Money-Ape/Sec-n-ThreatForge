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

        if result.executable.get("format") == "PE":
            table.add_row("PE Format", result.executable.get("pe_format", "Unknown"))
            table.add_row("Image Base", result.executable.get("image_base", "Unknown"))
            table.add_row("Subsystem", result.executable.get("subsystem", "Unknown"))
            table.add_row("Timestamp", str(result.executable.get("timestamp", "Unknown")))
            table.add_row("Characteristics", result.executable.get("characteristics", "Unknown"))

    table.add_row("SHA-256", result.hashes["sha256"])
    table.add_row("Entropy", str(result.entropy))
    table.add_row("Strings", str(len(result.strings)))
    table.add_row("Findings", str(len(result.findings)))
    table.add_row("Risk Score", str(result.risk.get("score", 0)))
    table.add_row("Classification", result.risk.get("classification", "UNKNOWN"))
    table.add_row("Base Score", str(result.risk.get("base_score", 0)))
    table.add_row("Context Bonus", str(result.risk.get("context_bonus", 0)))

    if result.risk.get("context_reasons", []):
        console.print("[bold]Contextual Risk Factors[/bold]")

        for reason in result.risk.get("context_reasons", []):
            console.print(f"  • {reason}")

        console.print()

    console.print()
    console.print(table)
    console.print()

    if result.executable and result.executable.get("sections"):
        console.print("[bold]Executable Sections[/bold]")

        section_table = Table()
        if result.executable.get("format") == "PE":
            section_table.add_column("Name")
            section_table.add_column("Virtual Size")
            section_table.add_column("Raw Size")
            section_table.add_column("RVA")
            section_table.add_column("Permissions")

            for section in result.executable["sections"]:
                section_table.add_row(
                    section.get("name", "<unknown>"),
                    str(section.get("virtual_size", "-")),
                    str(section.get("raw_size", "-")),
                    section.get("virtual_address", "-"),
                    section.get("permissions", "-"),
                )

        else:
            section_table.add_column("Name")
            section_table.add_column("Type")
            section_table.add_column("Size")
            section_table.add_column("Flags")

            for section in result.executable["sections"]:
                section_table.add_row(
                    section.get("name", "<unknown>"),
                    section.get("type", "-"),
                    str(section.get("size", "-")),
                    section.get("flags", "-"),
                )

        console.print(section_table)
        console.print()

    if result.executable.get("imports", []):
        console.print("[bold]PE Imports[/bold]")

        for library in result.executable.get("imports", []):
            console.print(f"[bold]{library.get('dll', '<unknown>')}[/bold]")

            for function in library.get("functions", []):
                if function.get("import_type") == "ORDINAL":
                    console.print(f"  • Ordinal {function.get('ordinal', '-')}")

                else:
                    console.print(f"  • {function.get('name', '<unknown>')}")

        console.print()

    if result.executable.get("exports", []):
        console.print("[bold]PE Exports[/bold]")

        export_table = Table()
        export_table.add_column("Name")
        export_table.add_column("Ordinal")
        export_table.add_column("RVA")

        for export in result.executable.get("exports", []):
            export_table.add_row(
                export.get("name", "<unknown>"),
                str(export.get("ordinal", "-")),
                export.get("rva", "-")
            )

        console.print(export_table)
        console.print()

    dependencies = result.executable.get("dependencies", [])
    if dependencies:
        console.print("[bold]Dependencies[/bold]")
        for dependency in dependencies:
            console.print(f"  • {dependency}")

        console.print()

    if result.executable.get("symbols", []):
        console.print("[bold]Dynamic Symbols[/bold]")

        symbol_table = Table()
        symbol_table.add_column("Name")
        symbol_table.add_column("Value")
        symbol_table.add_column("Size")
        symbol_table.add_column("Section")
        symbol_table.add_column("Binding")
        symbol_table.add_column("Type")

        for symbol in result.executable["symbols"]:
            symbol_table.add_row(
                symbol.get("name", "<unknown>"),
                symbol.get("value", "-"),
                str(symbol.get("size", "-")),
                str(symbol.get("section_index", "-")),
                symbol.get("binding", "-"),
                symbol.get("type", "-"),
            )

        console.print(symbol_table)
        console.print()

    if result.findings:
        console.print("[bold]Findings[/bold]")

        for finding in result.findings:
            rule_name = (finding.get("indicator") or finding.get("signature") or finding.get("type", "unknown"))

            console.print(f"  • [{rule_name}] {finding.get("description", "Unknown finding")} (severity: {finding.get("severity", 0)})")

            if finding.get("matched_string"):
                console.print(f"    Evidence: {finding["matched_string"]}")

            elif finding.get("library") and finding.get("function"):
                console.print(f"    Evidence: {finding["library"]}!{finding["function"]}")

            elif finding.get("section"):
                console.print(f"    Evidence: {finding["section"]} ({finding.get("permissions", "-")})")

            elif finding.get("value") is not None:
                console.print(f"    Evidence: {finding["value"]}")

        console.print()