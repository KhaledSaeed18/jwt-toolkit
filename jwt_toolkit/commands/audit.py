import json

import click
from rich.panel import Panel
from rich.table import Table

from jwt_toolkit.cli.console import console
from jwt_toolkit.cli.decoding import JSON_SCHEMA_VERSION, safe_decode
from jwt_toolkit.core.auditor import Grade, Report, Severity, run_audit

# Audit command — decodes a JWT, runs the security auditor, and emits a verdict.
# Static checks only; no signature verification or key resolution.


_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.WARN: "yellow",
    Severity.INFO: "cyan",
    Severity.PASS: "green",
}

_GRADE_STYLES: dict[Grade, tuple[str, str]] = {
    Grade.A: ("SECURE",    "green"),
    Grade.B: ("WEAK",      "yellow"),
    Grade.C: ("WEAK",      "yellow"),
    Grade.F: ("INSECURE",  "red"),
}


@click.command(help="Audit a JWT and emit a security verdict.")
@click.argument("token")
@click.option(
    "--strict",
    is_flag=True,
    help="Treat WARN findings as failures (exit 1).",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a machine-readable report. Schema is experimental.",
)
def audit(token: str, strict: bool, as_json: bool):
    decoded = safe_decode(token, as_json=as_json)
    report = run_audit(decoded.header, decoded.payload)
    exit_code = _resolve_exit_code(report, strict=strict)

    if as_json:
        _emit_json(decoded.header, decoded.payload, decoded.signature, report, exit_code, strict)
    else:
        _emit_rich(decoded.header, decoded.payload, decoded.signature, report)

    raise SystemExit(exit_code)


def _resolve_exit_code(report: Report, *, strict: bool) -> int:
    # Grade F is always a hard failure. --strict promotes any WARN to a failure too.
    if report.grade is Grade.F:
        return 1
    if strict and report.counts.get(Severity.WARN, 0) > 0:
        return 1
    return 0


def _emit_json(
    header: dict,
    payload: dict,
    signature: str,
    report: Report,
    exit_code: int,
    strict: bool,
) -> None:
    verdict, _ = _GRADE_STYLES[report.grade]
    document = {
        "schema_version": JSON_SCHEMA_VERSION,
        "grade": report.grade.value,
        "verdict": verdict,
        "exit_code": exit_code,
        "strict": strict,
        "counts": {s.value: report.counts.get(s, 0) for s in Severity},
        "header": header,
        "payload": payload,
        "signature_present": bool(signature),
        "findings": [
            {
                "severity": f.severity.value,
                "field": f.field,
                "message": f.message,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
    }
    click.echo(json.dumps(document, indent=2, sort_keys=False, default=str))


def _emit_rich(header: dict, payload: dict, signature: str, report: Report) -> None:
    console.print(Panel(json.dumps(header, indent=2),  title="Header",    border_style="blue"))
    console.print(Panel(json.dumps(payload, indent=2), title="Payload",   border_style="blue"))
    console.print(Panel(signature or "(none)",         title="Signature", border_style="blue"))
    console.print(_render_verdict(report))
    console.print(_render_findings_table(report))
    footer = _render_footer(report)
    if footer is not None:
        console.print(footer)


def _render_verdict(report: Report) -> Panel:
    verdict, colour = _GRADE_STYLES[report.grade]
    counts = report.counts
    summary = (
        f"[{colour}]Verdict : {verdict}[/{colour}]\n"
        f"[bold {colour}]Grade   : {report.grade.value}[/bold {colour}]\n\n"
        f"[dim]CRITICAL : {counts.get(Severity.CRITICAL, 0)}   "
        f"WARN : {counts.get(Severity.WARN, 0)}   "
        f"INFO : {counts.get(Severity.INFO, 0)}   "
        f"PASS : {counts.get(Severity.PASS, 0)}[/dim]"
    )
    return Panel(summary, title=f"[bold {colour}]Security Verdict[/bold {colour}]", border_style=colour)


def _render_findings_table(report: Report) -> Table:
    # Skip the Recommendation column when nothing has one — keeps the table
    # compact in the common case where every finding is a PASS.
    show_recs = any(f.recommendation for f in report.findings)

    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Field", width=14)
    table.add_column("Detail")
    if show_recs:
        table.add_column("Recommendation", style="dim")

    for f in report.findings:
        colour = _SEVERITY_COLORS[f.severity]
        row = [
            f"[{colour}]{f.severity.value}[/{colour}]",
            f.field,
            f.message,
        ]
        if show_recs:
            row.append(f.recommendation or "")
        table.add_row(*row)

    return table


def _render_footer(report: Report) -> Panel | None:
    # Surface the next command to run based on which findings actually fired.
    hints: list[str] = []
    fields = {f.field for f in report.findings if f.severity in (Severity.CRITICAL, Severity.WARN)}

    if "alg" in fields:
        hints.append("[dim]Test the HMAC secret strength : [/dim]jwt-toolkit crack <token> <wordlist>")
    if fields & {"alg", "exp", "kid", "jwk", "jku", "x5u"}:
        hints.append("[dim]Generate a strong secret      : [/dim]jwt-toolkit generate-secret")

    if not hints:
        return None
    return Panel("\n".join(hints), title="Next steps", border_style="blue")
