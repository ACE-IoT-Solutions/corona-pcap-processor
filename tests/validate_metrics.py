#!/usr/bin/env python
"""
Validate Corona metrics files against the Corona standard.
Uses the validate_model.py script from the Corona standard repository.

This script also provides utilities to generate metrics from PCAP files
and then validate them in a single step.
"""

import argparse
import logging
import os
import subprocess
import sys
import tempfile
from typing import Optional

# Add parent directory to path to access refactored modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bacnet_analyzer import BACnetAnalyzer
from bacnet_analyzer.corona_metrics import CoronaMetricsGenerator


def validate_metrics_file(
    metrics_file: str,
    analyze: bool = False,
    corona_standard_dir: Optional[str] = None,
) -> bool:
    """
    Validate a metrics file against the Corona standard.

    Args:
        metrics_file: Path to the metrics file to validate (TTL format)
        analyze: Whether to analyze the metrics file and print statistics
        corona_standard_dir: Path to the Corona standard repository
                            (defaults to ../corona-standard)

    Returns:
        True if validation succeeded, False otherwise
    """
    # Determine the path to the Corona standard repository
    if not corona_standard_dir:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.normpath(os.path.join(current_dir, ".."))
        corona_standard_dir = os.path.normpath(os.path.join(project_root, "corona-standard"))

    if not os.path.exists(corona_standard_dir):
        logging.error(f"Error: Corona standard repository not found at {corona_standard_dir}")
        logging.error(
            "Please make sure the Corona standard repository is available at this location."
        )
        return False

    # Validate the metrics file using the validate_model.py script
    validator_script = os.path.join(corona_standard_dir, "validate_model.py")
    if not os.path.exists(validator_script):
        logging.error(f"Error: Validator script not found at {validator_script}")
        logging.error("Please make sure the Corona standard repository contains validate_model.py.")
        return False

    # Build the command
    cmd = [sys.executable, validator_script]
    if analyze:
        cmd.append("--analyze")
    cmd.append(metrics_file)

    # Run the validation
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Validation failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        logging.error(f"Error: Python interpreter not found at {sys.executable}")
        return False


def process_pcap_and_validate(
    pcap_file: str,
    output_file: Optional[str] = None,
    capture_device: Optional[str] = None,
    analyze: bool = False,
    debug: bool = False,
    debug_level: int = 1,
    corona_standard_dir: Optional[str] = None,
) -> bool:
    """
    Process a PCAP file, generate Corona metrics, and validate them.

    Args:
        pcap_file: Path to the PCAP file to process
        output_file: Path to write the metrics file to (optional)
        capture_device: BACnet address of the device used to capture packets
        analyze: Whether to analyze the metrics after validation
        debug: Enable debug output
        debug_level: Debug verbosity level (1-3)
        corona_standard_dir: Path to the Corona standard repository
                           (defaults to ../corona-standard)

    Returns:
        True if processing and validation succeeded, False otherwise
    """
    if not os.path.exists(pcap_file):
        logging.error(f"Error: PCAP file not found: {pcap_file}")
        return False

    try:
        # Configure logging
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

        # Process the PCAP file
        analyzer = BACnetAnalyzer(debug=debug, debug_level=debug_level)
        logging.info(f"Analyzing PCAP file: {pcap_file}")
        results = analyzer.analyze_pcap(pcap_file)

        # Generate metrics
        metrics_gen = CoronaMetricsGenerator(results, capture_device)
        metrics_gen.generate_metrics()

        # Create tempfile if no output file specified
        if not output_file:
            fd, output_file = tempfile.mkstemp(suffix=".ttl")
            os.close(fd)
            temp_file_created = True
        else:
            temp_file_created = False

        # Export metrics
        metrics_gen.export_ttl(output_file)
        logging.info(f"Metrics exported to: {output_file}")

        # Validate metrics
        validation_result = validate_metrics_file(output_file, analyze, corona_standard_dir)

        # Clean up temporary file if created
        if temp_file_created and os.path.exists(output_file):
            os.unlink(output_file)

        return validation_result

    except Exception as e:
        logging.error(f"Error processing PCAP file: {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Validate Corona metrics files against the Corona standard."
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a metrics file")
    validate_parser.add_argument("metrics_file", help="The metrics file to validate (TTL format)")
    validate_parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze the metrics file and print statistics",
    )
    validate_parser.add_argument(
        "--corona-standard-dir",
        help="Path to the Corona standard repository (defaults to ../corona-standard)",
    )

    # Process command
    process_parser = subparsers.add_parser(
        "process", help="Process a PCAP file, generate metrics, and validate them"
    )
    process_parser.add_argument("pcap_file", help="The PCAP file to process")
    process_parser.add_argument("--output", help="Path to write the metrics file to (optional)")
    process_parser.add_argument(
        "--capture-device",
        help="BACnet address of the device used to capture packets",
    )
    process_parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze the metrics file and print statistics",
    )
    process_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output",
    )
    process_parser.add_argument(
        "--debug-level",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="Debug verbosity level (1-3)",
    )
    process_parser.add_argument(
        "--corona-standard-dir",
        help="Path to the Corona standard repository (defaults to ../corona-standard)",
    )

    # Parse arguments
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Handle commands
    if args.command == "validate":
        success = validate_metrics_file(args.metrics_file, args.analyze, args.corona_standard_dir)
        sys.exit(0 if success else 1)

    elif args.command == "process":
        success = process_pcap_and_validate(
            args.pcap_file,
            args.output,
            args.capture_device,
            args.analyze,
            args.debug,
            args.debug_level,
            args.corona_standard_dir,
        )
        sys.exit(0 if success else 1)

    else:
        # If no command provided, show help
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
