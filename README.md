# Corona BACnet PCAP Processor

[![CI](https://github.com/aceiot/corona-pcap-processor/actions/workflows/ci.yml/badge.svg)](https://github.com/aceiot/corona-pcap-processor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aceiot/corona-pcap-processor/branch/main/graph/badge.svg)](https://codecov.io/gh/aceiot/corona-pcap-processor)

A Python tool for analyzing BACnet network traffic from PCAP files and generating Corona-compatible metrics.

## Features

- Processes PCAP files containing BACnet traffic
- Discovers BACnet devices through I-Am messages
- Identifies BACnet/IP, MS/TP and remote network devices
- Detects forwarded messages from BACnet routers and BBMDs
- Aggregates statistics per BACnet address
  - Total packet count
  - Message type distribution
  - Routed vs. non-routed messages
  - Unicast vs. broadcast messages
  - Forwarded packet counts
- Maintains a comprehensive device cache with network addressing information
- Generates Corona-compatible metrics in Turtle (.ttl) RDF format

## Components

### Main PCAP Analyzer (`main.py`)

The main analyzer processes PCAP files containing BACnet traffic:

```bash
python main.py <pcap_file> [--debug]
```

### Corona Metrics Generator

Generates Corona-compatible metrics from the PCAP analysis using the rdflib library:

```bash
# Using the convenience wrapper script
./corona-metrics <pcap_file> <output_ttl_file> [--capture-device=<address>] [--debug]

# Or directly with the module
python corona_metrics.py <pcap_file> <output_ttl_file> [--capture-device=<address>] [--debug]
```

### Testing

Run the test suite to verify functionality:

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_metrics.py

# Run a specific test
python -m pytest tests/test_metrics.py::TestSpecificPcapContent::test_whohas_ihave_support
```

### Project Structure

```
corona-pcap-processor/
├── main.py                  # Main BACnet PCAP analyzer
├── corona_metrics.py        # Metrics generator using rdflib
├── corona-metrics           # Convenience wrapper script
├── tests/                   # Test suite directory
│   ├── __init__.py          # Package marker
│   ├── test_metrics.py      # Tests for metrics generator
│   ├── test_pcap_processor.py # Tests for PCAP processor
│   └── validate_metrics.py  # Utility to validate metrics against Corona standard
├── pcaps/                   # Sample PCAP files
├── *.pcap, *.pcap.gz        # Various sample PCAP files for testing
└── *.bak                    # Backup files (older implementations)

## Requirements

- Python 3.13+
- bacpypes3
- python-libpcap
- rdflib
- pytest (for running tests)

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/corona-pcap-processor.git
cd corona-pcap-processor

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -e .
```

## Usage

```bash
# Basic usage
python main.py <pcap_file>

# Enable debug mode for detailed packet inspection
python main.py <pcap_file> --debug
```

## Sample Output

```
=== BACnet Traffic Analysis ===

Address Statistics:

  10.21.52.12:
    Total Packets: 1347
    Message Types: {'BACnet/IP': 449, 'OriginalUnicastNPDU': 449, 'ReadPropertyACK': 449}
    Routed: 0, Non-Routed: 1347
    Unicast: 1347, Broadcast: 0

  10.21.86.4:
    Total Packets: 3460
    Message Types: {'BACnet/IP': 1730, 'ForwardedNPDU': 1730}
    Routed: 1730, Non-Routed: 1730
    Unicast: 3460, Broadcast: 0
    Forwarded Packets: 1730

=== Discovered BACnet Devices ===

  Device ID: 389001
    Address: BACnet/IP 10.0.1.47
    Properties: Vendor ID: 15, Max APDU: 1476, Segmentation: segmentedBoth

  Device ID: 450001
    Address: BACnet Network 5:0a1547c8
    Properties: Vendor ID: 8, Max APDU: 1024, Segmentation: segmentedBoth

  Device ID: 123456
    Address: BACnet MS/TP 5:01
    Properties: Vendor ID: 10, Max APDU: 480
    ---
    Address: Forwarded via 10.21.86.4
    Properties: Vendor ID: 10, Max APDU: 480
    Summary: 1 BACnet/IP, 1 remote network instances of this device
```

## Recent Improvements

The codebase has been substantially improved with the following changes:

- Refactored metrics generation to use `rdflib` instead of string manipulation
- Improved metric naming with sender-focused naming convention for clarity
- Added support for WhoHas/IHave BACnet message types
- Restructured the project with a dedicated tests directory
- Enhanced test coverage with comprehensive test cases
- Optimized MS/TP device detection and address handling

## Architecture

- Uses `bacpypes3.analysis.decode_file` to parse PCAP files
- Extracts BACnet messages, including forwarded NPDUs
- Identifies devices through I-Am announcements with address resolution
- Distinguishes between direct BACnet/IP and remote MS/TP devices
- Maintains statistics per BACnet address (both IP and network addresses)
- Supports debug mode for detailed packet inspection

