# BACnet PCAP Processor with Corona Metrics

A toolkit for analyzing BACnet packet captures (PCAP files), processing message types, extracting device information, and generating Corona-compatible metrics.
Meant to implement the [Corona Framework Metrics](https://github.com/ACE-IoT-Solutions/corona-framework)

## Features

- Analyzes BACnet packet captures (.pcap files)
- Detects and classifies message types by service choice
- Extracts device information from I-Am messages
- Handles both direct BACnet/IP messages and forwarded NPDUs
- Supports MS/TP devices through router forwarding
- Generates detailed traffic statistics and device reports
- Exports metrics in multiple formats:
  - TTL (Turtle) format for RDF/Corona compatibility
  - Project Haystack Zinc Grid format
  - Project Haystack JSON format
  - Prometheus exposition format with OpenTelemetry conventions
- Validates metrics against the Corona standard

## Project Structure

The main components of the project are:

- `bacnet_analyzer/` - Refactored functional implementation
  - `analyzer.py` - Main PCAP analyzer implementation
  - `corona_metrics.py` - Corona metrics generator
  - `models.py` - Data models for analysis results
  - `constants.py` - Constants for BACnet message types
  - `packet_processors.py` - Functions for processing BACnet packets
  - `device_catalog.py` - Device discovery and management
  - `stats_collector.py` - Statistics collection
  - `reporting.py` - Report generation
  - `debug_utils.py` - Debug utilities

- `tests/` - Test suite
  - `test_metrics.py` - Tests for the metrics generator
  - `test_pcap_processor.py` - Tests for the PCAP processor
  - `validate_metrics.py` - Utility for validating metrics files

## Installation

No installation required, just clone the repository and ensure you have the required dependencies:

```bash
pip install bacpypes3 rdflib
```

## Usage

### Analyzing PCAP Files

```python
from bacnet_analyzer import BACnetAnalyzer

# Create an analyzer instance (with optional debug mode)
analyzer = BACnetAnalyzer(debug=False, debug_level=1)

# Analyze a PCAP file
results = analyzer.analyze_pcap("sample-pcap.pcap")

# Print a summary of the analysis
analyzer.print_summary(results)
```

### Generating Metrics

```python
from bacnet_analyzer import BACnetAnalyzer
from bacnet_analyzer.corona_metrics import CoronaMetricsGenerator

# Analyze a PCAP file
analyzer = BACnetAnalyzer()
results = analyzer.analyze_pcap("sample-pcap.pcap")

# Generate metrics (optionally with a capture device address)
metrics_gen = CoronaMetricsGenerator(results, capture_device="10.0.0.1")
metrics_gen.generate_metrics()

# Export in different formats
metrics_gen.export_ttl("metrics.ttl")                  # RDF Turtle format
metrics_gen.export_haystack_zinc("metrics.zinc")       # Haystack Zinc format
metrics_gen.export_haystack_json("metrics.json")       # Haystack JSON format
metrics_gen.export_prometheus("metrics.prom")          # Prometheus exposition format
```

### Using the Command-Line Tools

#### Validate Metrics

```bash
# Validate a metrics file
python tests/validate_metrics.py validate metrics.ttl

# Validate with analysis
python tests/validate_metrics.py validate metrics.ttl --analyze
```

#### Process PCAP and Generate Metrics

```bash
# Process a PCAP file and generate metrics (default TTL format)
python generate_corona_metrics.py sample-pcap.pcap metrics.ttl

# Process with capture device
python generate_corona_metrics.py sample-pcap.pcap metrics.ttl --capture-device 10.0.0.1

# Generate in Haystack Zinc format
python generate_corona_metrics.py sample-pcap.pcap metrics.zinc --format zinc

# Generate in Haystack JSON format
python generate_corona_metrics.py sample-pcap.pcap metrics.json --format json

# Generate in Prometheus format with OpenTelemetry conventions
python generate_corona_metrics.py sample-pcap.pcap metrics.prom --format prom

# Generate with debug output
python generate_corona_metrics.py sample-pcap.pcap metrics.ttl --debug
```

## BACnet Message Detection

The analyzer detects BACnet message types in two ways:

1. **Class-based detection**: Looks at the APDU class names
2. **Service choice-based detection**: Uses the `apduService` attribute:
   - Service Choice 0: "IAmRequest"
   - Service Choice 1: "IHaveRequest"
   - Service Choice 7: "WhoHasRequest" 
   - Service Choice 8: "WhoIsRequest"

## Metrics Export Formats

The package can generate BACnet metrics in multiple formats:

### Corona Metrics (TTL)

Metrics in a format compatible with the Corona standard using RDF Turtle format:

- Uses RDF triples to represent metrics and relationships
- Follows the Corona metrics ontology for compatibility
- Enables semantic queries and integration with RDF tools
- Supports relationship modeling between devices and interfaces

### Project Haystack (Zinc and JSON)

Metrics in Project Haystack format for building automation systems:

- **Zinc Grid Format**: Compact, human-readable tabular format
- **JSON Format**: Project Haystack encoded in standard JSON

Haystack exports organize metrics with:
- Row-based representation of each metric
- Device and metric tagging
- Standard Haystack metadata

### Prometheus with OpenTelemetry Conventions

Metrics in Prometheus exposition format following OpenTelemetry semantic conventions:

- **Text-based format**: Standard Prometheus exposition format
- **OpenTelemetry compliance**: Follows OTel naming and labeling conventions
- **Counter and gauge support**: Properly categorizes metrics by type
- **Rich metadata**: Includes help text and type information

Example metrics in Prometheus format:
```
# HELP bacnet_packets_total Total number of BACnet packets observed from this device
# TYPE bacnet_packets_total counter
bacnet_packets_total{device_id="709101",address="0:10.21.86.4",network="0",name="Device 709101",address_type="bacnet_ip"} 5052

# HELP bacnet_whois_requests_total Number of WhoIs requests sent by this device
# TYPE bacnet_whois_requests_total counter
bacnet_whois_requests_total{device_id="709101",address="0:10.21.86.4",network="0",name="Device 709101",address_type="bacnet_ip"} 1579
```

All export formats cover the same metrics:

- Network interface metrics (broadcasts, unicasts, etc.)
- Application-level metrics (requests, responses by type)
- Router-specific metrics (forwarded messages, etc.)
- Device identification information

See the `corona-standard/README.md` file for details on the Corona standard format.

## Architecture

The analyzer follows a functional architecture with the following components:

### Design Principles

1. **Immutable data structures**: Uses immutable or copied structures
2. **Pure functions**: Functions with explicit inputs and outputs
3. **Separation of concerns**: Each module has a single responsibility
4. **No hidden state**: All state changes are explicit
5. **Type safety**: Comprehensive type hints

## Debugging Utilities

Several debugging utilities are provided to help with packet inspection:

- `debug_pcap.py`: General packet inspection
- `find_whohas.py`: Specifically looks for WHO-HAS messages
- `process_whohas.py`: Enhanced analyzer for WHO-HAS processing

## License

This project is licensed under the MIT License.