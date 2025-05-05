#!/usr/bin/env python
import logging
import sys
import traceback
from enum import Enum
from typing import Optional

# Assuming bacnet_analyzer is installed or accessible in the Python path
# If it's a local module, adjust the import accordingly
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
        output_format: Format to output the metrics in (TTL, ZINC, JSON, PROM)
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
        # TODO: Verify BACnetAnalyzer import path if it's a local module
        analyzer = BACnetAnalyzer(debug=debug, debug_level=debug_level)
        results = analyzer.analyze_pcap(pcap_file)

        # Generate metrics
        print("Generating BACnet metrics...")
        # TODO: Verify CoronaMetricsGenerator import path if it's a local module
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
            # This case should ideally not be reached due to click validation
            raise ValueError(f"Unsupported output format: {output_format}")

        print(f"BACnet metrics exported successfully to {output_file}")
    except Exception as e:
        print(f"Error generating metrics: {e}")
        traceback.print_exc()
        sys.exit(1)
