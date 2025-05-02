# BACnet PCAP Processor with Corona Metrics

A toolkit for analyzing BACnet packet captures (PCAP files), processing message types, extracting device information, and generating Corona-compatible metrics.

## Features

- Analyzes BACnet packet captures (.pcap files)
- Detects and classifies message types by service choice
- Extracts device information from I-Am messages
- Handles both direct BACnet/IP messages and forwarded NPDUs
- Supports MS/TP devices through router forwarding
- Generates detailed traffic statistics and device reports
- Generates Corona-compatible metrics in TTL (Turtle) format
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

- `corona-standard/` - Corona standard reference
  - `README.md` - Documentation for the Corona standard
  - `validate_model.py` - Tool for validating metrics against the standard
  - `example.ttl` - Example metrics file

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

### Generating Corona Metrics

```python
from bacnet_analyzer import BACnetAnalyzer
from bacnet_analyzer.corona_metrics import CoronaMetricsGenerator

# Analyze a PCAP file
analyzer = BACnetAnalyzer()
results = analyzer.analyze_pcap("sample-pcap.pcap")

# Generate metrics (optionally with a capture device address)
metrics_gen = CoronaMetricsGenerator(results, capture_device="10.0.0.1")
metrics_gen.generate_metrics()

# Export to TTL format
metrics_gen.export_ttl("metrics.ttl")
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
# Process a PCAP file and generate metrics
python tests/validate_metrics.py process sample-pcap.pcap --output metrics.ttl

# Process with capture device
python tests/validate_metrics.py process sample-pcap.pcap --output metrics.ttl --capture-device 10.0.0.1

# Process, generate metrics, and validate in one step
python tests/validate_metrics.py process sample-pcap.pcap --analyze
```

## BACnet Message Detection

The analyzer detects BACnet message types in two ways:

1. **Class-based detection**: Looks at the APDU class names
2. **Service choice-based detection**: Uses the `apduService` attribute:
   - Service Choice 0: "IAmRequest"
   - Service Choice 1: "IHaveRequest"
   - Service Choice 7: "WhoHasRequest" 
   - Service Choice 8: "WhoIsRequest"

## Corona Metrics

The package can generate metrics in a format compatible with the Corona standard, which is useful for:

- Tracking device behavior and performance
- Measuring network traffic patterns
- Analyzing broadcast and routed traffic
- Identifying device types and communication patterns

Metrics are generated in Turtle (.ttl) format, using RDF triples. These metrics cover:

- Network interface metrics (broadcasts, unicasts, etc.)
- Application-level metrics (requests, responses by type)
- Router-specific metrics (forwarded messages, etc.)
- Device identification information

See the `corona-standard/README.md` file for details on the standard.

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