#!/usr/bin/env python
"""
BACnet PCAP Analyzer
A functional implementation of the BACnet packet analyzer.
"""

import sys
import argparse
import logging

from bacnet_analyzer import BACnetAnalyzer


def main():
    """Main entry point for the BACnet PCAP Analyzer."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Analyze BACnet packets in PCAP files")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument(
        "--debug-level", type=int, choices=[1, 2, 3], default=1, 
        help="Debug verbosity level (1-3, higher is more verbose)"
    )
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s"
    )
    
    # Create analyzer
    analyzer = BACnetAnalyzer(debug=args.debug, debug_level=args.debug_level)
    
    try:
        # Process the PCAP file
        print(f"Analyzing {args.pcap_file}...")
        results = analyzer.analyze_pcap(args.pcap_file)
        
        # Print summary
        analyzer.print_summary(results)
    except Exception as e:
        print(f"Error analyzing file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()