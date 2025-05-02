#!/usr/bin/env python
"""
BACnet Corona Metrics Generator CLI
Analyzes a BACnet PCAP file and generates Corona-compatible metrics.
"""

import argparse
import logging
import sys
import traceback
from typing import Optional

from bacnet_analyzer import BACnetAnalyzer
from bacnet_analyzer.corona_metrics import CoronaMetricsGenerator


def process_pcap_and_generate_metrics(
    pcap_file: str,
    output_file: str,
    capture_device: Optional[str] = None,
    debug: bool = False,
    debug_level: int = 1,
) -> None:
    """
    Process a PCAP file and generate Corona metrics in one step.

    Args:
        pcap_file: Path to the PCAP file to analyze
        output_file: Path to write the output TTL file
        capture_device: Optional address of the device used to capture the traffic
        debug: Enable debug output
        debug_level: Debug verbosity level (1-3)
    """
    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    try:
        # Create and run the analyzer
        print(f"Analyzing {pcap_file}...")
        analyzer = BACnetAnalyzer(debug=debug, debug_level=debug_level)
        results = analyzer.analyze_pcap(pcap_file)

        # Generate metrics
        print("Generating Corona metrics...")
        metrics_gen = CoronaMetricsGenerator(results, capture_device)
        metrics_gen.generate_metrics()

        # Export metrics
        print(f"Exporting metrics to {output_file}...")
        metrics_gen.export_ttl(output_file)

        print(f"Corona metrics exported successfully to {output_file}")
    except Exception as e:
        print(f"Error generating metrics: {e}")
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Generate Corona-compatible metrics from BACnet PCAP files"
    )

    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("output_file", help="Path to write the output TTL file")
    parser.add_argument(
        "--capture-device", help="Optional address of the device used to capture the traffic"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument(
        "--debug-level",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="Debug verbosity level (1-3, higher is more verbose)",
    )

    args = parser.parse_args()

    process_pcap_and_generate_metrics(
        args.pcap_file,
        args.output_file,
        capture_device=args.capture_device,
        debug=args.debug,
        debug_level=args.debug_level,
    )


if __name__ == "__main__":
    main()
