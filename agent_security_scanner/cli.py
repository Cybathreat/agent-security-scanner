"""
Command-Line Interface for Agent Security Scanner.

Provides CLI for running security scans on AI agents, RAG pipelines,
and agent frameworks.

Usage:
    python -m agent_security_scanner.cli scan --target <url> --output output/
    python -m agent_security_scanner.cli scan --target <url> --modules prompt_injection,rag_security
    python -m agent_security_scanner.cli --help

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from loguru import logger

from .core.config import QualityGateConfig, load_config
from .core.engine import ScanEngine
from .core.logging import setup_logger
from .core.quality_gate import GateThreshold, evaluate as evaluate_gate
from .modules.base import ScanResult, Severity
from .output.json_report import JSONReport
from .output.markdown_report import MarkdownReport


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command-line arguments.

    Args:
        args: Command-line arguments (default: sys.argv[1:])

    Returns:
        Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="agent-security-scanner",
        description="AI Security Tool for auditing LLM agents, RAG pipelines, and agent frameworks.",
        epilog="Examples:\n"
        "  python -m agent_security_scanner.cli scan --target https://api.example.com\n"
        "  python -m agent_security_scanner.cli scan --target https://api.example.com --modules prompt_injection\n"
        "  python -m agent_security_scanner.cli scan --target https://api.example.com --format json --output report.json\n"
        "  python -m agent_security_scanner.cli web --port 8000 --reload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.2.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan on target")

    scan_parser.add_argument(
        "--target",
        "-t",
        type=str,
        required=True,
        help="Target URL or API endpoint to scan",
    )

    scan_parser.add_argument(
        "--modules",
        "-m",
        type=str,
        default="all",
        help="Comma-separated modules to run (default: all). "
        "Options: misconfigurations, prompt_injection, tool_boundaries, "
        "rag_security, tool_hijacking, recursive_agents, memory_poisoning, "
        "planning_attacks, secret_scanner, dependency_audit, plugin_security",
    )

    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="output",
        help="Output directory for reports (default: output)",
    )

    scan_parser.add_argument(
        "--format",
        "-f",
        type=str,
        choices=["json", "markdown", "both"],
        default="both",
        help="Output format (default: both)",
    )

    scan_parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Path to YAML configuration file",
    )

    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )

    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    scan_parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load config and modules without executing scan",
    )

    scan_parser.add_argument(
        "--fail-on",
        type=str,
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Minimum severity that triggers quality gate failure (default: critical)",
    )

    scan_parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Maximum total findings allowed before quality gate fails",
    )

    scan_parser.add_argument(
        "--max-risk-score",
        type=int,
        default=None,
        help="Maximum aggregate risk score allowed before quality gate fails",
    )

    # Web command
    web_parser = subparsers.add_parser("web", help="Start web dashboard server")

    web_parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )

    web_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)",
    )

    web_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )

    web_parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    # Config command
    config_parser = subparsers.add_parser("config", help="Show or generate configuration")

    config_parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate default config file",
    )

    config_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="config/config.yaml",
        help="Output path for generated config",
    )

    return parser.parse_args(args)


def run_web(args: argparse.Namespace) -> None:
    """
    Start the web dashboard server.

    Args:
        args: Parsed command-line arguments.
    """
    setup_logger(
        log_dir="logs",
        level=args.log_level,
        serialize=False,
    )

    try:
        import uvicorn

        from .web.app import create_app

        app = create_app()
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level=args.log_level.lower(),
        )
    except ImportError:
        print(
            "Web dependencies not installed. Install with: "
            "pip install -e '.[web]'",
            file=sys.stderr,
        )
        sys.exit(1)


def run_scan(args: argparse.Namespace) -> List[ScanResult]:
    """
    Execute security scan on target.

    Args:
        args: Parsed command-line arguments

    Returns:
        List[ScanResult]: Results from all executed modules.
    """
    # Setup logging
    setup_logger(
        log_dir="logs",
        level=args.log_level,
        serialize=False,
    )

    # Load configuration
    config = load_config(args.config)

    modules = None if args.modules == "all" else [m.strip() for m in args.modules.split(",")]

    engine = ScanEngine(config)
    return engine.run(args.target, modules=modules, timeout=args.timeout)


def generate_reports(
    results: List[ScanResult],
    args: argparse.Namespace,
    gate_threshold: Optional[GateThreshold] = None,
) -> None:
    """
    Generate output reports from scan results.

    Args:
        results: Scan results from all modules
        args: Parsed command-line arguments
        gate_threshold: Optional quality gate threshold for JSON report
    """
    output_dir = args.output

    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    target = results[0].target if results else "unknown"

    # JSON report
    if args.format in ["json", "both"]:
        json_reporter = JSONReport(
            pretty_print=True,
            include_timestamp=True,
        )
        report = json_reporter.generate(results, gate_threshold=gate_threshold)
        json_path = json_reporter.save(report, output_dir)
        logger.info(f"JSON report saved: {json_path}")

    # Markdown report
    if args.format in ["markdown", "both"]:
        md_reporter = MarkdownReport(
            include_timestamp=True,
            verbose=args.verbose,
        )
        md_report = md_reporter.generate(results, target)
        md_path = md_reporter.save(md_report, output_dir)
        logger.info(f"Markdown report saved: {md_path}")


def generate_config(output_path: str) -> None:
    """
    Generate default configuration file.

    Args:
        output_path: Path to save config file
    """
    config_content = """# Agent Security Scanner Configuration
# Generated by: python -m agent_security_scanner.cli config --generate

scanner:
  timeout: 30
  max_retries: 3
  rate_limit: 10.0
  user_agent: "AgentSecurityScanner/0.1"
  verify_ssl: true

modules:
  misconfigurations:
    enabled: true
    test_auth: true
    test_cors: true
    test_rate_limit: true
    test_info_disclosure: true

  prompt_injection:
    enabled: true
    detect_obfuscation: true
    detect_leakage: true
    test_crescendo: true
    test_many_shot: true
    test_skeleton_key: true

  tool_boundaries:
    enabled: true
    check_permissions: true
    audit_sandbox: true

  rag_security:
    enabled: true
    check_poisoning: true
    check_exfiltration: true
    vector_db_scan: true

  tool_hijacking:
    enabled: true
    test_tool_override: true
    test_parameter_injection: true
    test_response_manipulation: true

  recursive_agents:
    enabled: true
    test_recursive_creation: true
    test_agent_loop: true
    test_resource_exhaustion: true

  memory_poisoning:
    enabled: true
    test_false_memory: true
    test_memory_injection: true
    test_context_manipulation: true

  planning_attacks:
    enabled: true
    test_goal_hijacking: true
    test_plan_injection: true
    test_priority_manipulation: true

  secret_scanner:
    enabled: true
    test_hardcoded_secrets: true
    test_env_exposure: true
    test_log_leakage: true

  dependency_audit:
    enabled: true
    test_outdated_deps: true
    test_vulnerabilities: true
    test_license_compliance: true

  plugin_security:
    enabled: true
    test_plugin_permissions: true
    test_plugin_isolation: true
    test_plugin_integrity: true

output:
  format: "both"
  output_dir: "output"
  pretty_print: true
  include_timestamp: true
  verbose: false

quality_gate:
  fail_on_severity: "critical"
  # max_findings: 50
  # max_risk_score: 100

logging:
  level: "INFO"
  format: "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {function} | {message}"
  rotation: "10 MB"
  retention: "7 days"
  compression: "zip"
  serialize: false
"""

    # Create parent directories
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write config
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(config_content)

    logger.info(f"Configuration generated: {output_path}")


def _build_gate_threshold(
    args: argparse.Namespace,
    config_quality_gate: QualityGateConfig,
) -> Optional[GateThreshold]:
    """
    Build quality gate threshold from CLI args and config.

    CLI args take precedence over config file values.

    Args:
        args: Parsed CLI arguments.
        config_quality_gate: Quality gate config from file.

    Returns:
        GateThreshold, or None if quality gate is explicitly disabled.
    """
    # Resolve severity: CLI > config > default (critical)
    severity_str = args.fail_on or config_quality_gate.fail_on_severity
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    fail_on_severity = severity_map.get(severity_str.lower(), Severity.CRITICAL)

    # Resolve max_findings: CLI > config
    max_findings = (
        args.max_findings if args.max_findings is not None else config_quality_gate.max_findings
    )

    # Resolve max_risk_score: CLI > config
    max_risk_score = (
        args.max_risk_score
        if args.max_risk_score is not None
        else config_quality_gate.max_risk_score
    )

    return GateThreshold(
        fail_on_severity=fail_on_severity,
        max_findings=max_findings,
        max_risk_score=max_risk_score,
    )


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for CLI.

    Args:
        args: Command-line arguments

    Returns:
        int: Exit code (0 = success, 1 = error, 2 = quality gate failed)
    """
    parsed = parse_args(args)

    if parsed.command == "scan":
        try:
            # Run scan
            results = run_scan(parsed)

            # Build quality gate threshold from CLI args + config
            config = load_config(parsed.config)
            gate_threshold = _build_gate_threshold(parsed, config.quality_gate)

            # Generate reports (pass gate threshold for JSON report)
            generate_reports(results, parsed, gate_threshold=gate_threshold)

            # Evaluate quality gate
            gate_result = evaluate_gate(results, gate_threshold)

            # Print summary
            total_findings = sum(len(r.findings) for r in results)
            critical = gate_result.summary.get("critical", 0)
            high = gate_result.summary.get("high", 0)
            medium = gate_result.summary.get("medium", 0)
            low = gate_result.summary.get("low", 0)
            info = gate_result.summary.get("info", 0)

            print(f"\n{'=' * 60}")
            print("SCAN COMPLETE")
            print(f"{'=' * 60}")
            print(f"Target: {parsed.target}")
            print(f"Modules: {parsed.modules}")
            print(f"Total Findings: {total_findings}")
            print(f"  Critical: {critical}")
            print(f"  High: {high}")
            print(f"  Medium: {medium}")
            print(f"  Low: {low}")
            print(f"  Info: {info}")
            print(f"Risk Score: {gate_result.risk_score}")
            print(f"Quality Gate: {'PASSED' if gate_result.passed else 'FAILED'}")
            print(f"  {gate_result.reason}")
            print(f"Output: {parsed.output}/")
            print(f"{'=' * 60}\n")

            return gate_result.exit_code

        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            print(f"Error: {e}", file=sys.stderr)
            return 1

    elif parsed.command == "web":
        run_web(parsed)
        return 0

    elif parsed.command == "config":
        if parsed.generate:
            generate_config(parsed.output)
            return 0
        else:
            print("Use --generate to create config file")
            return 0

    else:
        print("No command specified. Use --help for usage.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
