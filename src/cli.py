#!/usr/bin/env python
"""
BACnet Corona Metrics Generator CLI
Analyzes a BACnet PCAP file and generates Corona-compatible metrics.
Supports multiple output formats including TTL, Haystack Zinc, Haystack JSON, and Prometheus.
"""

import click
import os
from typing import Optional

# Import from the processor module within the same package
from processor import OutputFormat, process_pcap_and_generate_metrics


@click.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("output_file", type=click.Path(dir_okay=False))
@click.option(
    "--format",
    "output_format_str",  # Use a different name to avoid conflict with the 'format' built-in
    type=click.Choice([f.value for f in OutputFormat], case_sensitive=False),
    default=OutputFormat.TTL.value,
    help="Output format: ttl (RDF Turtle), zinc (Haystack Zinc), json (Haystack JSON), or prom (Prometheus).",
    show_default=True,
)
@click.option(
    "--capture-device",
    help="Optional address of the device used to capture the traffic.",
)
@click.option("--debug", is_flag=True, help="Enable debug output.")
@click.option(
    "--debug-level",
    type=click.IntRange(1, 3),
    default=1,
    help="Debug verbosity level (1-3, higher is more verbose).",
    show_default=True,
)
def main(
    pcap_file: str,
    output_file: str,
    output_format_str: str,
    capture_device: Optional[str],
    debug: bool,
    debug_level: int,
):
    """Generate metrics from BACnet PCAP files in various formats."""
    output_format_enum = OutputFormat(output_format_str)

    # If no extension is provided in the output file, add it based on the format
    if not os.path.splitext(output_file)[1]:
        if output_format_enum == OutputFormat.TTL:
            output_file += '.ttl'
        elif output_format_enum == OutputFormat.ZINC:
            output_file += '.zinc'
        elif output_format_enum == OutputFormat.JSON:
            output_file += '.json'
        elif output_format_enum == OutputFormat.PROM:
            output_file += '.prom'

    process_pcap_and_generate_metrics(
        pcap_file,
        output_file,
        output_format=output_format_enum,
        capture_device=capture_device,
        debug=debug,
        debug_level=debug_level,
    )


if __name__ == "__main__":
    main()
