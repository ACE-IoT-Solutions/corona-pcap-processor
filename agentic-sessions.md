# Corona PCAP Processor Agentic Sessions

## Session 7: Multi-format Metrics Export

### Summary
In this session, we significantly enhanced the metrics export capabilities, adding support for multiple industry-standard formats:

1. **Project Haystack Export Formats**
   - Implemented Zinc Grid format export, providing a compact, human-readable tabular representation
   - Added JSON-encoded Haystack export for programmatic access and integration
   - Maintained all device information and metrics across formats

2. **Prometheus Export with OpenTelemetry Conventions**
   - Created a standard Prometheus exposition format exporter
   - Implemented OpenTelemetry semantic conventions for metric naming and labeling
   - Properly categorized metrics as counters and gauges
   - Added comprehensive help text and type information

3. **Command-line Interface Enhancements**
   - Added format selection option to the CLI (--format)
   - Implemented automatic file extension handling
   - Created detailed usage documentation

4. **Comprehensive Testing**
   - Added unit tests for all export formats
   - Created CLI tests for format selection
   - Added tests for empty results handling

### Key Changes

#### Multi-format Export Methods

We added three new export methods to the `CoronaMetricsGenerator` class:

```python
# Export to Project Haystack Zinc Grid format
def export_haystack_zinc(self, output_file: str) -> None:
    """Export the metrics in Project Haystack Zinc Grid format."""
    # Implementation details...

# Export to Project Haystack JSON format
def export_haystack_json(self, output_file: str) -> None:
    """Export the metrics in Project Haystack JSON format."""
    # Implementation details...

# Export to Prometheus format
def export_prometheus(self, output_file: str) -> None:
    """Export the metrics in Prometheus exposition format with OpenTelemetry semantic conventions."""
    # Implementation details...
```

#### CLI Format Selection

We enhanced the command-line interface to support format selection:

```python
class OutputFormat(Enum):
    """Output format options for metrics."""
    TTL = "ttl"  # RDF Turtle format
    ZINC = "zinc"  # Project Haystack Zinc Grid format
    JSON = "json"  # Project Haystack JSON format
    PROM = "prom"  # Prometheus exposition format
    
# Add format selection to the parser
parser.add_argument(
    "--format",
    type=OutputFormat,
    choices=list(OutputFormat),
    default=OutputFormat.TTL,
    help="Output format: ttl (RDF Turtle), zinc (Haystack Zinc), json (Haystack JSON), or prom (Prometheus)"
)
```

#### Prometheus with OpenTelemetry Conventions

For the Prometheus format, we implemented OpenTelemetry naming conventions:

```python
# Map our metrics to OTel convention metric names
metric_name_map = {
    "packetsReceived": "packets_total",
    "totalBacnetMessagesSent": "messages_sent_total",
    "whoIsRequestsSent": "whois_requests_total",
    # More mappings...
}

# Define metric types
metric_types = {
    # Counters
    "packetsReceived": "counter",
    # Gauges
    "routedDevicesSeen": "gauge",
    # More type mappings...
}
```

### Benefits

1. **Improved Integration**: Support for multiple formats allows integration with different systems
2. **Industry Standards**: Implements two major standards (Haystack and Prometheus/OpenTelemetry)
3. **Flexible Deployment**: Same data can be used with building automation or cloud monitoring
4. **Future-proof**: Support for modern observability stacks
5. **Comprehensive Testing**: Ensures all formats work correctly

### Future Improvements

1. **Real-time Metrics**: Add support for real-time metrics streaming
2. **Additional Formats**: Consider adding InfluxDB Line Protocol or other time-series formats
3. **Metric Aggregation**: Add support for aggregating metrics across multiple captures
4. **Visualization Templates**: Create starter dashboards for Grafana or other tools

## Session 6: Project Structure and Metrics Updates

### Summary
In this session, we made significant updates to the project structure and fixed issues with metrics generation:

1. **Fixed ReportedBy Relation Issue**
   - Removed `corona:reportedBy` relation from metrics that shouldn't include it
   - Maintained proper device/interface relationships via `bacnet:contains` property
   - Fixed self-referential `reportedBy` in interface-only entries

2. **Modernized Project Structure with src Layout**
   - Migrated to a proper Python package structure with `src/bacnet_analyzer`
   - Updated imports and references across the codebase
   - Updated test configuration and GitHub workflows for new structure
   - Set up proper package management via pyproject.toml
   - Made the package fully installable via pip

### Key Changes

#### Removing reportedBy Relation

We removed the `corona:reportedBy` relation from our metrics to ensure compliance with the Corona standard:

```python
# Old implementation in _add_device_to_graph
# Add relationship to parent device
self.graph.add((interface_uri, self.CORONA.reportedBy, device_uri))

# New implementation
# Relationship to parent device is handled by the BACNET.contains property
```

For interface-only entries, we also removed the self-referential relationship:

```python
# Old implementation
# For interface-only entries, they report themselves
self.graph.add((interface_uri, self.CORONA.reportedBy, interface_uri))

# New implementation
# Interface-only entries don't need a reportedBy relation
```

#### Implementing src Layout

The src-layout pattern ensures proper package isolation and installation, avoiding common Python packaging issues:

```
project/
├── src/
│   └── bacnet_analyzer/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── corona_metrics.py
│       └── ...
├── tests/
│   ├── __init__.py
│   ├── test_pcap_processor.py
│   └── ...
└── pyproject.toml
```

We updated the package configuration in pyproject.toml:

```toml
packages = [
    { include = "bacnet_analyzer", from = "src" },
]
```

The pythonpath configuration was updated for tests:

```toml
[tool.pytest.ini_options]
pythonpath = [".", "src"]
```

#### GitHub CI/CD Updates

We updated the GitHub Actions workflow to work with the new structure:

```yaml
# Updated test command to use the new path structure
- name: Test with pytest
  run: |
    pytest tests/ --cov=src/bacnet_analyzer --cov-report=xml
```

### Benefits

1. **Improved Package Isolation**: The src-layout ensures that the package runs the same way when installed or in development
2. **Better Dependency Management**: Explicit package configuration makes dependencies more predictable
3. **Proper Packaging**: Project can now be properly distributed and installed via pip
4. **Compliant Metrics**: Removed incorrect relationships from metrics to ensure standard compliance
5. **Maintainable Structure**: Code organization follows modern Python best practices
6. **CI/CD Improvements**: GitHub workflows updated to handle the new structure properly

### Future Improvements

1. **Type Hints Completion**: Add complete type hints across all modules
2. **Command Line Interface**: Add proper CLI entry points using setuptools
3. **Documentation**: Add API documentation with autobuilding
4. **Code Coverage**: Improve test coverage for better reliability
5. **Package Publishing**: Set up automated releases to PyPI

## Session 5: WHO-HAS Support and Metrics Validation

### Summary
In this session, we enhanced the Corona PCAP Processor with several crucial improvements:

1. **Complete Refactoring to Functional Architecture**
   - Migrated the codebase to a clean package structure in `bacnet_analyzer/`
   - Implemented immutable data structures with pure functions
   - Separated concerns into distinct modules with clear interfaces
   - Added comprehensive type hints for better type safety
   - Reduced code complexity through functional programming patterns

2. **WHO-HAS and I-HAVE Message Support**
   - Added detection and metrics for WHO-HAS and I-HAVE BACnet messages
   - Properly accounted for broadcast vs. directed requests
   - Ensured metrics capture these service types correctly

3. **Metrics Validation System**
   - Created a robust `validate_metrics.py` script with two commands:
     - `validate`: Validates existing TTL metrics files
     - `process`: Processes PCAP files to generate and validate metrics
   - Implemented proper error handling and status reporting
   - Added support for detailed metrics analysis

4. **Corona Standard Reference Implementation**
   - Created a `corona-standard` directory with standard documentation
   - Added `validate_model.py` script for metrics validation
   - Provided example TTL file demonstrating standard-compliant metrics

### Key Changes

#### Functional Refactoring
We reorganized the entire codebase into a modular package structure:

```python
# Core analyzer implementation with immutable state handling
def analyze_pcap(self, filepath: str) -> AnalysisResults:
    """Analyze a PCAP file and extract BACnet information."""
    # Initialize empty results
    results = AnalysisResults()
    
    # Process each frame in the PCAP file
    for frame in decode_file(filepath):
        # Process the frame and update results
        results = self._process_frame(frame, results)
    
    return results

def _process_frame(self, frame: any, results: AnalysisResults) -> AnalysisResults:
    """Process a BACnet frame and update the analysis results."""
    # Create mutable copies of the result collections for updating
    address_stats = results.address_stats.copy()
    device_cache = results.device_cache.copy()
    
    # Process the frame and update stats
    # ...
    
    # Create updated results
    updated_results = AnalysisResults(
        address_stats=address_stats,
        device_cache=device_cache,
    )
    
    return updated_results
```

#### Metrics Validation Tool

We created a comprehensive validation tool with a clean command-line interface:

```python
def main():
    parser = argparse.ArgumentParser(
        description="Validate Corona metrics files against the Corona standard."
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a metrics file")
    validate_parser.add_argument(
        "metrics_file", help="The metrics file to validate (TTL format)"
    )
    validate_parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze the metrics file and print statistics",
    )
    # ...
    
    # Process command
    process_parser = subparsers.add_parser(
        "process", 
        help="Process a PCAP file, generate metrics, and validate them"
    )
    process_parser.add_argument(
        "pcap_file", help="The PCAP file to process"
    )
    # ...
```

#### WHO-HAS Support

Extended the corona_metrics.py implementation to properly handle WHO-HAS and I-HAVE messages:

```python
# Handle WhoHas/IHave requests
if "WhoHasRequest" in stats.message_types:
    count = stats.message_types["WhoHasRequest"]
    device_metrics["whoHasRequestsSent"] += count
    device_metrics["globalWhoHasRequestsSent"] += count
    total_requests += count

if "IHaveRequest" in stats.message_types:
    count = stats.message_types["IHaveRequest"]
    device_metrics["iHaveResponsesSent"] += count
    total_responses += count
```

#### Corona Standard Documentation

Created comprehensive Corona standard documentation with examples:

```markdown
## Key Metrics

### Network Interface Metrics

- `packetsReceived` - Total packets observed from this device
- `totalBacnetMessagesSent` - Total BACnet messages sent by this device
- `broadcastPacketsSent` - Broadcast packets sent by this device
- `totalBroadcastsSent` - Total broadcast messages sent by this device
- `globalBroadcastMessageCount` - Count of global broadcasts from this device

### Application Metrics

- `whoIsRequestsSent` - WhoIs requests sent by this device
- `globalWhoIsRequestsSent` - Global WhoIs requests sent by this device
- `directedWhoIsRequestsSent` - Directed WhoIs requests sent by this device
- `iAmResponsesSent` - IAm responses sent by this device
- `whoHasRequestsSent` - WhoHas requests sent by this device
- `globalWhoHasRequestsSent` - Global WhoHas requests sent by this device
- `directedWhoHasRequestsSent` - Directed WhoHas requests sent by this device
- `iHaveResponsesSent` - IHave responses sent by this device
```

### Benefits

1. **Improved Maintainability**: The functional architecture ensures clear data flow and immutability
2. **Enhanced Type Safety**: Comprehensive type hints prevent runtime errors
3. **Better Testing**: Separation of concerns makes unit testing more effective
4. **Robust Validation**: Users can now validate metrics against standards easily
5. **Complete WHO-HAS Support**: The analyzer now handles all common BACnet discovery protocols
6. **Developer-Friendly**: Clean interfaces make it easier for new developers to contribute

### Implementation Details

#### Data Models and Immutability

We used frozen dataclasses to enforce immutability:

```python
@dataclass(frozen=True)
class AnalysisResults:
    """Results of analyzing a BACnet PCAP file."""
    address_stats: Dict[str, AddressStats] = field(default_factory=dict)
    device_cache: Dict[str, DeviceInfo] = field(default_factory=dict)
```

#### Service Choice Handling

Added explicit mapping from service choices to message types:

```python
class ServiceChoice(Enum):
    """BACnet service choices."""
    I_AM = 0
    I_HAVE = 1
    WHO_HAS = 7
    WHO_IS = 8

SERVICE_CHOICE_TO_TYPE: Final[Dict[int, str]] = {
    ServiceChoice.I_AM.value: "IAmRequest",
    ServiceChoice.I_HAVE.value: "IHaveRequest",
    ServiceChoice.WHO_HAS.value: "WhoHasRequest",
    ServiceChoice.WHO_IS.value: "WhoIsRequest",
}
```

#### RDF Export Improvements

Enhanced the TTL export functionality with proper header comments:

```python
def export_ttl(self, output_file: str) -> None:
    """Export the metrics in Corona-compatible Turtle (.ttl) format."""
    # Add a header comment with timestamp
    header = f"""# Corona BACnet metrics generated from PCAP analysis
# Generated on: {datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}

# BACnet devices and properties use the bacnet: namespace
# Metrics and other Corona-specific properties use the corona: namespace
"""

    # Serialize the graph to Turtle format
    ttl_data = self.graph.serialize(format="turtle")

    # Write to file with header
    with open(output_file, "w") as f:
        f.write(header)
        f.write(ttl_data)
```

### Future Improvements

1. **Performance Optimization**: Further optimize packet processing for large PCAP files
2. **Additional Metrics**: Add more detailed metrics for other BACnet service types
3. **Visualization**: Add graphical visualization of the metrics data
4. **Integration**: Add integration with BACnet monitoring tools
5. **Real-Time Processing**: Add support for real-time packet processing
6. **Packaging**: Implement proper Python package structure for distribution

## Session 4: CI/CD and Repository Setup

### Summary
In this session, we set up continuous integration and deployment infrastructure for the Corona PCAP Processor project:

1. **GitHub Actions Workflow**
   - Created CI/CD pipeline for testing and validating the code
   - Added multi-version Python testing (3.10, 3.11, 3.12, 3.13)
   - Implemented linting with ruff
   - Added type checking with mypy
   - Set up code coverage reporting with pytest-cov and Codecov

2. **Repository Configuration**
   - Enhanced .gitignore file for proper file exclusions
   - Updated README.md with CI status badges
   - Improved pyproject.toml with complete project metadata and tool configurations
   - Simplified codebase by renaming corona_metrics_rdflib.py to corona_metrics.py

3. **Validation Pipeline**
   - Added Corona standard validation as part of the CI pipeline
   - Ensured metrics output complies with the Corona standard

### Key Changes

#### CI Workflow Configuration
Created a comprehensive GitHub Actions workflow for CI/CD:

```yaml
name: Corona PCAP Processor CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12', '3.13']

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
        
    # More steps for testing, linting, etc.
```

#### Package Configuration
Enhanced the project's pyproject.toml with proper metadata and tool configurations:

```toml
[project]
name = "corona-pcap-processor"
version = "0.1.0"
description = "BACnet network traffic analyzer for PCAP files and Corona metrics generator"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [
    { name = "ACE IoT" },
]
dependencies = [
    "python-libpcap>=0.5.2",
    "bacpypes3>=0.2.8",
    "rdflib>=6.3.2",
]

# Tool configurations for pytest, ruff, mypy, black, etc.
```

### Benefits

1. **Quality Assurance**: Automated testing on every push and pull request
2. **Cross-Platform Compatibility**: Testing on multiple Python versions
3. **Code Quality**: Enforced consistency through linting and type checking
4. **Confidence**: Clear visibility of test status through GitHub UI and README badges
5. **Metrics Validation**: Automatic validation against the Corona standard specification

### Implementation Details

#### Test Coverage Reporting
Implemented detailed test coverage reporting:

```yaml
- name: Test with pytest
  run: |
    pytest tests/ --cov=. --cov-report=xml

- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
    fail_ci_if_error: false
```

#### Metrics Validation
Added a validation job to ensure metrics match the Corona standard:

```yaml
validate:
  runs-on: ubuntu-latest
  steps:
    # Setup steps...
    
    - name: Clone Corona Standard Repository
      uses: actions/checkout@v4
      with:
        repository: aceiot/corona-standard
        path: corona-standard
        
    - name: Generate sample metrics
      run: |
        python corona_metrics.py sample-pcap.pcap sample-metrics.ttl
        
    - name: Validate metrics against Corona standard
      run: |
        cd corona-standard
        python validate_model.py ../sample-metrics.ttl --analyze
```

### Future Improvements

1. **Deployment Pipeline**: Add automatic PyPI package publishing
2. **Pre-commit Hooks**: Implement pre-commit hooks for local development
3. **Documentation Site**: Automate generation and deployment of documentation
4. **Container Building**: Add Docker container building and publishing

### File Rename for Simplicity
Simplified the codebase by standardizing on a single metrics generator file:

```bash
# Renamed the file
mv corona_metrics_rdflib.py corona_metrics.py

# Updated import statements in dependent files
# Updated wrapper script
```

This change streamlines the codebase by:
1. Consolidating to a single canonical implementation
2. Simplifying imports and dependencies
3. Making the codebase more intuitive for new contributors

## Session 3: Project Restructuring and Cleanup

### Summary
In this session, we performed a comprehensive restructuring and cleanup of the Corona PCAP Processor project:

1. **Code Cleanup and Organization**
   - Moved unused debug and test files to backup (.bak) format for review
   - Created a dedicated tests directory with proper Python package structure
   - Fixed imports and references to ensure proper module discovery
   - Created a convenience wrapper script for easier execution

2. **Test Suite Improvements**
   - Updated test paths and imports for the new structure
   - Fixed test assertions to work with rdflib's output format
   - Ensured all tests pass consistently with the refactored code

3. **Documentation Updates**
   - Revised README.md to reflect project improvements and structure
   - Updated project structure documentation
   - Added clear usage instructions for both direct and wrapper script execution
   - Added documentation about recent improvements

### Key Changes

#### Project Structure
We reorganized the project with a cleaner structure:

```
corona-pcap-processor/
├── main.py                  # Main BACnet PCAP analyzer
├── corona_metrics_rdflib.py # Metrics generator using rdflib
├── corona-metrics           # Convenience wrapper script
├── tests/                   # Test suite directory
│   ├── __init__.py          # Package marker
│   ├── test_metrics.py      # Tests for metrics generator
│   ├── test_pcap_processor.py # Tests for PCAP processor
│   └── validate_metrics.py  # Utility to validate metrics against Corona standard
├── pcaps/                   # Sample PCAP files
├── *.pcap, *.pcap.gz        # Various sample PCAP files for testing
└── *.bak                    # Backup files (older implementations)
```

#### Test Module Updates
We updated test imports to work with the new directory structure:

```python
import sys
import os

# Add parent directory to path to access modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import BACnetPcapAnalyzer
from corona_metrics_rdflib import CoronaMetricsGenerator
```

#### Entry Point Script
We created a simple wrapper script to make execution easier:

```python
#!/usr/bin/env python
"""
Corona BACnet Metrics Generator CLI wrapper
"""

from corona_metrics_rdflib import main

if __name__ == "__main__":
    main()
```

### Benefits

1. **Improved organization**: Clear separation between core code and tests
2. **Better maintainability**: Cleaner project structure makes future development simpler
3. **Enhanced usability**: Easier to execute with the wrapper script
4. **Better testing**: More reliable test suite with proper package structure

### Implementation Details

#### Test Adaptations
Fixed test assertions to accommodate rdflib's Turtle serialization format:

```python
# Looking for either format depending on rdflib's serialization
network_interface_found = "a corona:NetworkInterfaceMetric" in content or \
                         "corona:NetworkInterfaceMetric" in content
self.assertTrue(network_interface_found,
            "NetworkInterfaceMetric type not found in TTL file")
```

#### Python Package Structure
Added proper package structure with `__init__.py` files for better module discovery and consistent imports.

### Future Improvements

1. **CI Integration**: Add GitHub Actions or similar CI pipelines for automated testing
2. **Documentation**: Add more detailed API documentation
3. **Deployment**: Implement proper packaging for PyPI distribution
4. **Config Files**: Add configuration file support for customizable behavior

## Session 2: Improved Metrics and WhoHas/IHave Support

### Summary
In this session, we improved the Corona metrics generation by:

1. **Eliminated ambiguous metric names**
   - Replaced generic metrics with explicit "Sent" versions to clearly indicate observed activity
   - Removed metrics that implied reception when we can only observe sending from a packet capture

2. **Added WhoHas/IHave message support**
   - Extended the metrics to track WhoHas requests
   - Added support for IHave responses 
   - Added proper testing for these message types

3. **Improved metric consistency**
   - Renamed totalRequests to totalRequestsSent
   - Renamed successfulResponses to totalResponsesSent
   - Ensured proper classification of messages as requests or responses

### Key Changes

#### Metric Improvements
We redesigned the metrics to focus only on observed actions:

```python
"whoIsRequestsSent": 0,       # WhoIs requests sent by this device
"iAmResponsesSent": 0,        # IAm responses sent by this device
"whoHasRequestsSent": 0,      # WhoHas requests sent by this device
"iHaveResponsesSent": 0,      # IHave responses sent by this device
"readPropertyRequestsSent": 0, # ReadProperty requests sent by this device
"readPropertyResponsesSent": 0, # ReadProperty responses sent by this device
"totalRequestsSent": 0,        # Total requests sent by this device
"totalResponsesSent": 0,       # Total responses sent by this device
```

#### Updated Update Method
We redesigned the _update_device_metrics method to properly categorize messages:

```python
# Handle WhoHas/IHave requests
if "WhoHasRequest" in stats.message_types:
    count = stats.message_types["WhoHasRequest"]
    device_metrics["whoHasRequestsSent"] += count
    device_metrics["globalWhoHasRequestsSent"] += count
    total_requests += count

if "IHaveRequest" in stats.message_types:
    count = stats.message_types["IHaveRequest"]
    device_metrics["iHaveResponsesSent"] += count
    total_responses += count
```

#### Added Unit Tests
We implemented specialized tests to verify the new metrics:

```python
def test_whohas_ihave_support(self):
    """Test specific support for WhoHas and IHave messages."""
    # Create an analyzer with a sample WhoHas/IHave packet
    analyzer = BACnetPcapAnalyzer()
    
    # Create a metrics generator with a simulated WhoHas/IHave interaction
    metrics_gen = CoronaMetricsGenerator(analyzer)
    
    # Manually inject some test metrics to simulate messages
    device_metrics = metrics_gen._initialize_metrics()
    
    # Simulate messages and verify correct metrics
    # ...
```

### Benefits

1. **More accurate metrics**: Metrics now accurately represent what was observed in the packet capture

2. **Clearer semantics**: Each metric has a clear and unambiguous meaning focused on source

3. **Better telemetry**: Added support for more BACnet message types for comprehensive monitoring

4. **Improved testing**: Added direct tests for the new metrics

### Implementation Details

The key insight in this implementation is that a PCAP capture only lets us observe packets that were sent by devices, not how they're received or processed. Therefore, all metrics should focus on the sender's perspective.

For example, rather than tracking both `whoIsRequestsSent` and `whoIsRequestsReceived`, we now only track `whoIsRequestsSent` as that's all we can definitively observe from the packet capture.

## Session 1: Refactoring to RDFLib and Test Suite Creation

### Summary
In this session, we accomplished two major improvements to the Corona PCAP Processor:

1. **Refactored Corona Metrics Generator using RDFLib**
   - Replaced manual string formatting with RDFLib's graph-based representations
   - Improved maintainability and flexibility of the code
   - Properly modeled BACnet and Corona metrics using standard RDF/OWL semantics
   - Added better typed literal support via XSD datatypes

2. **Created a comprehensive test suite**
   - Implemented tests for the BACnet PCAP analyzer functionality
   - Added tests for Corona metrics generation
   - Created tests for RDF graph structure validation
   - Added specific test cases for address handling and message processing
   - Implemented tests for the capture device feature

### Key Files

- **corona_metrics_rdflib.py**: Refactored implementation of the metrics generator
- **test_metrics.py**: Comprehensive test suite for PCAP analysis and metrics generation

### Major Improvements

#### RDFLib Implementation
The refactoring to RDFLib provides several advantages:

1. **Improved abstraction**: Using RDF triples provides a clean separation between data model and serialization
2. **Better type safety**: Using XSD datatypes ensures proper representation of literals
3. **More maintainability**: Less string manipulation leads to fewer bugs and more readable code
4. **Enhanced querying capabilities**: The graph structure allows for more sophisticated data analysis

#### Test Suite Design
The test suite provides comprehensive verification:

1. **BACnet Analysis Tests**:
   - Verifies that PCAPfiles are correctly processed
   - Ensures devices are properly identified
   - Validates forwarded packets detection

2. **Metrics Generation Tests**:
   - Checks that metrics are correctly collected from analyzer data
   - Validates RDF graph structure and relationships
   - Verifies TTL export functionality

3. **Specialized Tests**:
   - Tests for BACnet address parsing and handling
   - Validation of MS/TP MAC address conversion
   - Verification of consistency between different metrics
   - Testing of the capture device feature and observedFrom relationships

### Implementation Details

#### Address Type Detection
The address type detection logic was standardized and improved:

```python
@staticmethod
def _get_address_type(bacnet_address: str) -> Tuple[str, str, str, bool]:
    """
    Analyze a BACnet address and return its components and type.
    
    Args:
        bacnet_address: A BACnet address in the format "network:mac"
        
    Returns:
        A tuple containing (network, mac, address_type, is_mstp)
        where address_type is one of "ip", "mstp", or "network"
    """
    network = "0"
    mac = ""
    address_type = "ip"
    is_mstp = False
    
    if ":" in bacnet_address:
        parts = bacnet_address.split(":", 1)
        network = parts[0]
        mac = parts[1]
        
        # Check if this is a non-local network
        if network != "0":
            is_mstp = True
            
            # Determine if this is an MS/TP address (typically short MAC address)
            # or a general remote network address
            if len(mac) <= 4:
                address_type = "mstp"
            else:
                address_type = "network"
        else:
            # Local network with IP address
            address_type = "ip"
    
    return network, mac, address_type, is_mstp
```

#### RDF Graph Building
The RDF graph building was organized into specialized methods:

```python
def _build_rdf_graph(self):
    """Build the RDF graph from collected metrics."""
    # Add capture device if specified
    capture_device_uri = None
    if self.capture_device:
        # Create a URI for the capture device
        capture_device_uri = self.EX[f"capture_{clean_address}"]
        
        # Add the capture device to the graph
        self.graph.add((capture_device_uri, RDF.type, self.CORONA.CaptureDevice))
        # ...additional properties...
    
    # Add device and interface data
    for device_key, data in self.device_metrics.items():
        # Extract device info and metrics
        device_info = data["info"]
        metrics = data["metrics"]
        
        if isinstance(device_key, int):
            # This is a device with a device ID
            self._add_device_to_graph(device_key, device_info, metrics, capture_device_uri)
        else:
            # This is an interface-only entry
            self._add_interface_to_graph(device_key, device_info, metrics, capture_device_uri)
```

#### Capture Device Support
The capture device feature was enhanced to properly handle the Corona `observedFrom` relationship:

```python
# Add observedFrom relationship if capture device provided
if capture_device_uri:
    self.graph.add((interface_uri, self.CORONA.observedFrom, capture_device_uri))
```

### Challenges and Solutions

1. **MS/TP Address Formatting**
   - **Challenge**: MS/TP addresses needed to be converted from hex strings to integers
   - **Solution**: Added explicit hex-to-int conversion with error handling

2. **Metrics Consistency**
   - **Challenge**: Some metrics weren't consistently calculated
   - **Solution**: Added explicit handling for IAm responses to ensure they are counted as successful responses

3. **Graph Query Complexity**
   - **Challenge**: Working with RDF graphs requires different query patterns
   - **Solution**: Implemented helper methods to simplify graph construction and queries

### Future Improvements

1. **SPARQL Query Support**: Add support for more complex graph queries using SPARQL
2. **Error Handling**: Enhance error handling for malformed BACnet addresses
3. **Performance Optimization**: Optimize graph construction for large PCAP files
4. **Visualization**: Add RDF graph visualization tools for better analysis
5. **Ontology Expansion**: Further develop the Corona metrics ontology for richer representations