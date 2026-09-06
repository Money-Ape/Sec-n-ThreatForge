import click
from rich.console import Console

console = Console()

@click.group()
@click.version_option(version="0.1.0", prog_name="Sec-n-ThreatForge")
def cli():
    # Sec-n-ThreatForge security research framework
    pass

@cli.command()
def info():
    # Display framework information.
    console.print("[bold]Sec-n-ThreatForge[/bold]")
    console.print("Security, Threat Generation & Malware Analysis Framework")
    console.print("version : 0.1.0")

def main():
    cli()

if __name__=="__main__":
    main()