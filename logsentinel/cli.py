#!/usr/bin/env python3
"""
LogSentinel CLI entry point.

This module provides the command-line interface for LogSentinel,
a log-based threat detection tool.

Usage:
    logsentinel scan <logfile>

Exit codes:
    0: Success
    1: General error (invalid arguments, file errors, etc.)
    2: File not found
    3: Permission denied
    4: Invalid file format or corrupted file
"""

from __future__ import annotations

import argparse
import os
import sys
from enum import IntEnum
from pathlib import Path
from typing import NoReturn


class ExitCode(IntEnum):
    """UNIX exit codes for the CLI application."""

    SUCCESS = 0
    GENERAL_ERROR = 1
    FILE_NOT_FOUND = 2
    PERMISSION_DENIED = 3
    INVALID_FILE = 4


class CLIError(Exception):
    """Base exception for CLI-related errors."""

    def __init__(
        self, message: str, exit_code: ExitCode = ExitCode.GENERAL_ERROR
    ):
        """Initialize CLI error with message and exit code.

        Args:
            message: Error message to display to the user.
            exit_code: UNIX exit code to return.
        """
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


def validate_log_file_path(file_path: Path) -> None:
    """Validate that the log file path is acceptable.

    Args:
        file_path: Path to validate.

    Raises:
        CLIError: If the path is invalid, file doesn't exist,
            or is not readable.
    """
    if not file_path.is_absolute() and not file_path.exists():
        # Try to resolve relative path
        resolved_path = file_path.resolve()
        if not resolved_path.exists():
            raise CLIError(
                f"Log file not found: {file_path}",
                ExitCode.FILE_NOT_FOUND,
            )

    if not file_path.exists():
        raise CLIError(
            f"Log file not found: {file_path}",
            ExitCode.FILE_NOT_FOUND,
        )

    if not file_path.is_file():
        raise CLIError(
            f"Path is not a file: {file_path}",
            ExitCode.INVALID_FILE,
        )

    if not os.access(file_path, os.R_OK):
        raise CLIError(
            f"Permission denied: cannot read {file_path}",
            ExitCode.PERMISSION_DENIED,
        )

    # Check if file is empty (might be valid, but worth warning)
    if file_path.stat().st_size == 0:
        print(
            f"Warning: Log file is empty: {file_path}",
            file=sys.stderr,
        )


def read_log_file_safely(file_path: Path) -> list[str]:
    """Read log file with robust error handling.

    This function handles various failure scenarios:
    - File corruption (invalid encoding)
    - Permission issues (already checked, but double-check)
    - I/O errors during reading
    - Very large files (basic protection)

    Args:
        file_path: Path to the log file to read.

    Returns:
        List of log lines as strings.

    Raises:
        CLIError: If file cannot be read or is corrupted.
    """
    max_file_size_mb = 100  # Reasonable limit for production
    max_file_size_bytes = max_file_size_mb * 1024 * 1024

    file_size = file_path.stat().st_size
    if file_size > max_file_size_bytes:
        raise CLIError(
            f"File too large: {file_size / (1024 * 1024):.1f} MB "
            f"(max: {max_file_size_mb} MB). Use a smaller file or "
            "implement streaming processing.",
            ExitCode.INVALID_FILE,
        )

    lines: list[str] = []
    encodings_to_try = ["utf-8", "latin-1", "cp1252"]

    for encoding in encodings_to_try:
        try:
            with open(
                file_path, "r", encoding=encoding, errors="strict"
            ) as file:
                lines = file.readlines()
                break
        except UnicodeDecodeError as e:
            if encoding == encodings_to_try[-1]:
                # Last encoding failed, give up
                raise CLIError(
                    f"File encoding error: cannot decode {file_path} "
                    f"with common encodings. Error: {e}",
                    ExitCode.INVALID_FILE,
                ) from e
            # Try next encoding
            continue
        except PermissionError as e:
            raise CLIError(
                f"Permission denied while reading: {file_path}",
                ExitCode.PERMISSION_DENIED,
            ) from e
        except OSError as e:
            raise CLIError(
                f"I/O error while reading {file_path}: {e}",
                ExitCode.GENERAL_ERROR,
            ) from e

    return lines


def scan_log_file(log_file_path: Path) -> int:
    """Scan a log file for threats.

    This function orchestrates the scanning process:
    1. Validates the file
    2. Reads the file safely
    3. Processes through the analysis engine (to be implemented)
    4. Generates a report (to be implemented)

    Args:
        log_file_path: Path to the log file to scan.

    Returns:
        Number of threats detected (0 for now, until engine is implemented).

    Raises:
        CLIError: If scanning fails at any stage.
    """
    validate_log_file_path(log_file_path)

    try:
        log_lines = read_log_file_safely(log_file_path)
    except CLIError:
        raise
    except Exception as e:
        # Catch-all for unexpected errors
        raise CLIError(
            f"Unexpected error while reading log file: {e}",
            ExitCode.GENERAL_ERROR,
        ) from e

    if not log_lines:
        print(
            f"Warning: No log entries found in {log_file_path}",
            file=sys.stderr,
        )
        return 0

    # TODO: Integrate with logsentinel.engine when available
    # For now, this is a placeholder that validates the file is readable
    # In production, this would call:
    #   from logsentinel.engine import Engine
    #   engine = Engine()
    #   results = engine.scan(log_lines)
    #   report = generate_report(results)
    #   return len(results.threats)

    print(
        f"Scanned {len(log_lines)} log entries from {log_file_path}",
        file=sys.stdout,
    )

    return 0


def build_argument_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="LogSentinel: CLI tool for log-based threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  logsentinel scan /var/log/auth.log\n"
            "  logsentinel scan ./access.log\n"
            "\n"
            "Exit codes:\n"
            "  0: Success\n"
            "  1: General error\n"
            "  2: File not found\n"
            "  3: Permission denied\n"
            "  4: Invalid file format"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a log file for threats",
        description="Scan a log file for security threats and anomalies",
    )

    scan_parser.add_argument(
        "logfile",
        type=str,
        help="Path to the log file to scan",
        metavar="<logfile>",
    )

    return parser


def parse_arguments(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments with validation.

    Args:
        args: Optional list of arguments (for testing). If None, uses sys.argv.

    Returns:
        Parsed arguments namespace.

    Raises:
        CLIError: If arguments are invalid.
    """
    parser = build_argument_parser()

    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as exc:
        # argparse calls sys.exit() on error, we want to handle it ourselves
        if exc.code == 0:
            # Help or version was requested, exit normally
            sys.exit(0)
        raise CLIError(
            "Invalid arguments. Use 'logsentinel --help' "
            "for usage information.",
            ExitCode.GENERAL_ERROR,
        ) from exc

    return parsed_args


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI application.

    This function:
    1. Parses and validates arguments
    2. Executes the requested command
    3. Handles all errors explicitly
    4. Returns appropriate exit codes

    Args:
        args: Optional list of arguments (for testing). If None, uses sys.argv.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    try:
        parsed_args = parse_arguments(args)
    except CLIError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        return e.exit_code

    if parsed_args.command == "scan":
        log_file_path = Path(parsed_args.logfile)

        try:
            threat_count = scan_log_file(log_file_path)
            if threat_count > 0:
                print(
                    f"Warning: {threat_count} potential threat(s) detected",
                    file=sys.stderr,
                )
                # In production, might want to return non-zero exit code
                # if threats are found, depending on use case
            return ExitCode.SUCCESS
        except CLIError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            return e.exit_code
        except KeyboardInterrupt:
            print("\nInterrupted by user", file=sys.stderr)
            return ExitCode.GENERAL_ERROR
        except (OSError, IOError, MemoryError) as e:
            # Handle specific system-level errors that might occur
            print(
                f"System error: {e}",
                file=sys.stderr,
            )
            return ExitCode.GENERAL_ERROR
        except Exception as e:
            # Catch-all for truly unexpected errors
            # This is intentional: we want to handle ANY error gracefully
            # rather than crashing. In production, this should be logged
            # to a monitoring system for investigation.
            print(
                f"Unexpected error: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return ExitCode.GENERAL_ERROR
    else:
        # This should not happen if argparse is configured correctly
        print(
            f"Error: Unknown command: {parsed_args.command}",
            file=sys.stderr,
        )
        return ExitCode.GENERAL_ERROR


def cli_entry_point() -> NoReturn:
    """Entry point wrapper that calls sys.exit with proper exit code.

    This function is the actual entry point called when the script is executed.
    It ensures proper exit code propagation to the shell.
    """
    exit_code = main()
    sys.exit(exit_code)


if __name__ == "__main__":
    cli_entry_point()
