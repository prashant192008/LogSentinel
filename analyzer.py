from collections import Counter
import csv

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

console = Console()

def analyze_traffic(logs, top_n=5, export_path=None):
    """
    Calculates general statistics:
    - Total requests
    - Top N IP addresses
    - Number of 404 errors

    If export_path is provided, writes the top IPs to a CSV.
    """
    if not logs:
        console.print("[bold red]No log data to analyze.[/bold red]")
        return

    total_requests = len(logs)
    errors_404 = sum(1 for log in logs if log.get("status") == "404")
    ip_counter = Counter(log["ip"] for log in logs)
    top_ips = ip_counter.most_common(top_n)

    # ── Rich summary table ─────────────────────────────────────────────────
    table = Table(
        title=f"[bold cyan]LogSentinel — Traffic Summary[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
    )
    table.add_column("Metric", style="bold white", no_wrap=True)
    table.add_column("Value", justify="right", style="bright_green")

    table.add_row("Total Requests", str(total_requests))
    table.add_row("404 Errors", f"[bold red]{errors_404}[/bold red]")
    table.add_row("Unique IPs", str(len(ip_counter)))

    console.print()
    console.print(table)

    # ── Top N IPs table ────────────────────────────────────────────────────
    ip_table = Table(
        title=f"[bold cyan]Top {top_n} IP Addresses[/bold cyan]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold yellow",
        border_style="bright_blue",
    )
    ip_table.add_column("Rank", style="dim", justify="center")
    ip_table.add_column("IP Address", style="bold white")
    ip_table.add_column("Requests", justify="right", style="bright_green")

    for rank, (ip, count) in enumerate(top_ips, start=1):
        ip_table.add_row(str(rank), ip, str(count))

    console.print(ip_table)
    console.print()

    # ── Optional CSV export ────────────────────────────────────────────────
    if export_path:
        try:
            with open(export_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["rank", "ip_address", "request_count"])
                for rank, (ip, count) in enumerate(top_ips, start=1):
                    writer.writerow([rank, ip, count])
            console.print(f"[bold green][+] CSV exported to:[/bold green] {export_path}")
        except OSError as e:
            console.print(f"[bold red][ERROR] Could not write CSV: {e}[/bold red]")

def detect_brute_force(logs, threshold=5, endpoint_keyword="login"):
    """
    Identifies IPs that have made more than 'threshold' requests
    to paths containing 'endpoint_keyword'.
    """
    targeted = [
        log["ip"]
        for log in logs
        if endpoint_keyword.lower() in log.get("request", "").lower()
    ]

    ip_counts = Counter(targeted)
    threats = {ip: count for ip, count in ip_counts.items() if count > threshold}

    console.print()
    if not threats:
        console.print(
            Panel(
                Text(f"No brute-force attempts detected on endpoints containing '{endpoint_keyword}'.", justify="center"),
                title="[bold green]Threat Detection[/bold green]",
                border_style="green",
            )
        )
    else:
        for ip, count in threats.items():
            alert_text = Text(justify="center")
            alert_text.append("⚠  BRUTE-FORCE ALERT\n\n", style="bold red")
            alert_text.append(f"IP Address : ", style="bold white")
            alert_text.append(f"{ip}\n", style="bold yellow")
            alert_text.append(f"Endpoint   : ", style="bold white")
            alert_text.append(f"*{endpoint_keyword}*\n", style="bold cyan")
            alert_text.append(f"Requests   : ", style="bold white")
            alert_text.append(f"{count}  (threshold: {threshold})", style="bold red")

            console.print(
                Panel(
                    alert_text,
                    title="[bold red]⚠  THREAT DETECTED[/bold red]",
                    border_style="red",
                    padding=(1, 4),
                )
            )
    console.print()
