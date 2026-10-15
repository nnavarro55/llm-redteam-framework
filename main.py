import os
import sys
import json
import argparse
from datetime import datetime, timezone
from typing import Optional, List
from dotenv import load_dotenv
from google import genai
from rich.console import Console
from rich.table import Table

from schema import AuditMetadata, AuditReport, AdversarialPayload
from payloads import PAYLOAD_SUITE
from evaluator import SafetyEvaluator
from targets import BaseTarget, GeminiTarget, MockTarget

load_dotenv()
console = Console()

def run_red_team_suite(
    target: BaseTarget,
    evaluator: SafetyEvaluator,
    payloads: Optional[List[AdversarialPayload]] = None,
    output_path: str = "security_report.json"
) -> AuditReport:
    """Executes the red-teaming audit suite against the specified target."""
    test_suite = payloads if payloads is not None else PAYLOAD_SUITE

    console.print("[bold red]🛡️ Starting OWASP LLM Red Team Security Audit...[/bold red]")
    console.print(f"[dim]Target: {target.name} | Judge Model: {evaluator.judge_model}[/dim]")
    console.print(f"[dim]Payloads: {len(test_suite)} test cases loaded[/dim]\n")

    results = []
    for payload in test_suite:
        console.print(f"Executing [yellow]{payload.id}[/yellow] ({payload.category.value})...")
        
        # Query target and evaluate
        response = target.query(payload.prompt)
        result = evaluator.evaluate(payload, response)
        results.append(result)

    # Render Results Table
    table = Table(title="OWASP LLM Security Assessment Report")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Confidence", justify="right", style="cyan")
    table.add_column("Eval Method", style="blue")
    table.add_column("Reasoning", style="white")

    vulnerable_count = 0
    error_count = 0
    for r in results:
        if r.eval_method in ("System Error", "Judge Error", "Empty Response"):
            status = "[bold yellow]ERROR[/bold yellow]"
            error_count += 1
        elif r.vulnerable:
            status = "[bold red]VULNERABLE[/bold red]"
            vulnerable_count += 1
        else:
            status = "[bold green]PASSED[/bold green]"

        confidence_str = f"{r.confidence_score:.2f}"
        table.add_row(
            r.payload_id,
            r.category.name,
            status,
            confidence_str,
            r.eval_method,
            (r.reasoning[:55] + "...") if len(r.reasoning) > 55 else r.reasoning
        )

    console.print(table)
    
    total_tests = len(results)
    passed_count = total_tests - vulnerable_count - error_count
    pass_rate = round((passed_count / total_tests) * 100, 2) if total_tests > 0 else 0.0

    report = AuditReport(
        metadata=AuditMetadata(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_model=target.name,
            judge_model=evaluator.judge_model,
            total_tests=total_tests,
            passed=passed_count,
            vulnerable=vulnerable_count,
            errors=error_count,
            pass_rate_percent=pass_rate
        ),
        results=results
    )

    # Save JSON Report
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(mode="json"), f, indent=2)
        
    console.print(
        f"\nAudit completed: [bold red]{vulnerable_count}[/bold red] vulnerable, "
        f"[bold green]{passed_count}[/bold green] passed, "
        f"[bold yellow]{error_count}[/bold yellow] errors "
        f"([cyan]{pass_rate}% defense rate[/cyan])."
    )
    console.print(f"Report saved to [green]{output_path}[/green]")

    return report

def main():
    target_default = os.getenv("TARGET_MODEL") or "gemini-3.5-flash"
    judge_default = os.getenv("JUDGE_MODEL") or "gemini-3.5-flash"

    parser = argparse.ArgumentParser(
        description="OWASP LLM Red Teaming & Prompt Injection Testing Framework"
    )
    parser.add_argument(
        "--target-model",
        default=target_default,
        help=f"Target model identifier (default: {target_default})"
    )
    parser.add_argument(
        "--judge-model",
        default=judge_default,
        help=f"Judge model identifier (default: {judge_default})"
    )
    parser.add_argument(
        "--category",
        default=None,
        help="Filter payloads by OWASP category prefix (e.g. LLM01, LLM02, LLM05)"
    )
    parser.add_argument(
        "--output",
        default="security_report.json",
        help="Output path for the JSON audit report (default: security_report.json)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with non-zero code (1) if any vulnerabilities OR system/API errors occur (fails closed for CI/CD)"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run in offline mock mode without calling external APIs (no API key required)"
    )
    parser.add_argument(
        "--simulate-vulnerable",
        action="store_true",
        help="In mock mode, simulate vulnerable target responses to test CI failure conditions"
    )

    args = parser.parse_args()

    # Configure Target and Evaluator
    if args.mock:
        console.print("[cyan]ℹ️ Running in OFFLINE MOCK mode (no API key required).[/cyan]\n")
        target = MockTarget(simulate_vulnerable=args.simulate_vulnerable)
        evaluator = SafetyEvaluator(client=None, judge_model="mock-judge")
    else:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            console.print(
                "[bold red]❌ Error: GEMINI_API_KEY is not set.[/bold red]\n"
                "Please create a [yellow].env[/yellow] file or set the GEMINI_API_KEY environment variable.\n"
                "Example:\n  [cyan]GEMINI_API_KEY=your_gemini_api_key_here[/cyan]\n"
                "Tip: You can run offline tests using [yellow]--mock[/yellow]."
            )
            sys.exit(1)

        client = genai.Client()
        target = GeminiTarget(client=client, model=args.target_model)
        evaluator = SafetyEvaluator(client=client, judge_model=args.judge_model)

    # Filter payloads if requested
    payloads = PAYLOAD_SUITE
    if args.category:
        cat_filter = args.category.upper()
        payloads = [
            p for p in PAYLOAD_SUITE
            if p.category.name.startswith(cat_filter) or cat_filter in p.category.value.upper()
        ]
        if not payloads:
            console.print(f"[bold red]❌ No payloads found matching category '{args.category}'.[/bold red]")
            sys.exit(1)

    report = run_red_team_suite(
        target=target,
        evaluator=evaluator,
        payloads=payloads,
        output_path=args.output
    )

    if args.strict:
        failures = []
        if report.metadata.vulnerable > 0:
            failures.append(f"{report.metadata.vulnerable} vulnerability(ies) detected")
        if report.metadata.errors > 0:
            failures.append(f"{report.metadata.errors} system/API error(s) occurred")

        if failures:
            console.print(f"\n[bold red]❌ Audit failed strict check: {', '.join(failures)}.[/bold red]")
            sys.exit(1)

if __name__ == "__main__":
    main()
