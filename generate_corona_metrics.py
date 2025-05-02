#!/usr/bin/env python
"""
BACnet Corona Metrics Generator CLI
Analyzes a BACnet PCAP file and generates Corona-compatible metrics.
Supports multiple output formats including TTL, Haystack Zinc, and Haystack JSON.
"""

import argparse
import logging
import os
import sys
import traceback
from enum import Enum
from typing import Optional

from bacnet_analyzer import BACnetAnalyzer
from bacnet_analyzer.corona_metrics import CoronaMetricsGenerator


class OutputFormat(Enum):
    """Output format options for metrics."""
    TTL = "ttl"  # RDF Turtle format
    ZINC = "zinc"  # Project Haystack Zinc Grid format
    JSON = "json"  # Project Haystack JSON format
    PROM = "prom"  # Prometheus exposition format
    
    def __str__(self):
        return self.value


def process_pcap_and_generate_metrics(
    pcap_file: str,
    output_file: str,
    output_format: OutputFormat = OutputFormat.TTL,
    capture_device: Optional[str] = None,
    debug: bool = False,
    debug_level: int = 1,
) -> None:
    """
    Process a PCAP file and generate metrics in the specified format.

    Args:
        pcap_file: Path to the PCAP file to analyze
        output_file: Path to write the output file
        output_format: Format to output the metrics in (TTL, ZINC, or JSON)
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
        print("Generating BACnet metrics...")
        metrics_gen = CoronaMetricsGenerator(results, capture_device)
        metrics_gen.generate_metrics()

        # Export metrics in the specified format
        print(f"Exporting metrics in {output_format.value.upper()} format to {output_file}...")
        
        if output_format == OutputFormat.TTL:
            metrics_gen.export_ttl(output_file)
        elif output_format == OutputFormat.ZINC:
            metrics_gen.export_haystack_zinc(output_file)
        elif output_format == OutputFormat.JSON:
            metrics_gen.export_haystack_json(output_file)
        elif output_format == OutputFormat.PROM:
            metrics_gen.export_prometheus(output_file)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        print(f"BACnet metrics exported successfully to {output_file}")
    except Exception as e:
        print(f"Error generating metrics: {e}")
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Generate metrics from BACnet PCAP files in various formats"
    )

    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("output_file", help="Path to write the output file")
    parser.add_argument(
        "--format",
        type=OutputFormat,
        choices=list(OutputFormat),
        default=OutputFormat.TTL,
        help="Output format: ttl (RDF Turtle), zinc (Haystack Zinc), or json (Haystack JSON)"
    )
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
    
    # If no extension is provided in the output file, add it based on the format
    output_file = args.output_file
    if not os.path.splitext(output_file)[1]:
        if args.format == OutputFormat.TTL:
            output_file += '.ttl'
        elif args.format == OutputFormat.ZINC:
            output_file += '.zinc'
        elif args.format == OutputFormat.JSON:
            output_file += '.json'
        elif args.format == OutputFormat.PROM:
            output_file += '.prom'

    process_pcap_and_generate_metrics(
        args.pcap_file,
        output_file,
        output_format=args.format,
        capture_device=args.capture_device,
        debug=args.debug,
        debug_level=args.debug_level,
    )


if __name__ == "__main__":
    main()
