"""
BACnet Corona Metrics Generator
Generates Corona-compatible metrics from BACnet PCAP analysis using rdflib.
This module works with the functional BACnetAnalyzer implementation.
"""

import datetime
from collections import defaultdict
from typing import Any, Dict, Optional, Tuple, List, cast

import hszinc  # Added import
from rdflib import RDF, RDFS, XSD, Graph, Literal, Namespace

from .models import AddressStats, AnalysisResults


class CoronaMetricsGenerator:
    """Generates Corona-compatible metrics from BACnet PCAP analysis using rdflib."""

    def __init__(self, analysis_results: AnalysisResults, capture_device: Optional[str] = None):
        """
        Initialize with analysis results.

        Args:
            analysis_results: The BACnet PCAP analysis results
            capture_device: Optional address of the device used to capture the packets
        """
        self.address_stats = analysis_results.address_stats
        self.device_cache = analysis_results.device_cache
        self.device_metrics: Dict[Any, Dict[str, Any]] = {}  # Will hold per-device metrics
        self.capture_device = capture_device  # Store the capture device address if provided

        # Create an RDF graph
        self.graph = Graph()

        # Define namespaces
        self.RDF = RDF
        self.RDFS = RDFS
        self.XSD = XSD
        self.BACNET = Namespace("https://data.ashrae.org/bacnet/")
        self.CORONA = Namespace("http://example.org/standards/corona/metrics#")
        self.EX = Namespace("http://example.org/bacnet-impl/")

        # Bind namespaces to prefixes for pretty serialization
        self.graph.bind("rdf", RDF)
        self.graph.bind("rdfs", RDFS)
        self.graph.bind("xsd", XSD)
        self.graph.bind("bacnet", self.BACNET)
        self.graph.bind("corona", self.CORONA)
        self.graph.bind("ex", self.EX)

    def generate_metrics(self) -> None:
        """Process analyzer data and generate metrics."""
        # First collect the device info from the analyzer
        self._collect_device_metrics()
        self._build_rdf_graph()

    def _collect_device_metrics(self) -> None:
        """Extract metrics from the device cache and address_stats."""
        # First, collect all devices by their ID
        device_id_map = {}
        for device_addr, device_info in self.device_cache.items():
            # Skip duplicate device:id entries
            if device_addr.startswith("device:"):
                continue

            device_id = device_info.device_id
            device_id_map[device_id] = device_info

        # Process metrics for known devices with IDs
        for device_id, device_info in device_id_map.items():
            self.device_metrics[device_id] = {
                "info": device_info,
                "metrics": self._initialize_metrics(),
            }

            # Add address-specific stats for this device
            device_metrics = self.device_metrics[device_id]["metrics"]

            # For MS/TP devices, they may not have stats directly on their address,
            # but rather through the router that forwarded their messages.
            bacnet_address = device_info.bacnet_address
            if not bacnet_address:  # Add a check for None before calling _get_address_type
                continue
            network, mac, address_type, is_mstp = self._get_address_type(bacnet_address)

            # If this is an MS/TP or remote network device, it may not have direct stats - need special handling
            if is_mstp:
                # For MS/TP devices, assume they sent at least one IAm request
                device_metrics["iAmResponsesSent"] += 1

                # Set appropriate network type for metrics
                if address_type == "mstp":
                    device_metrics["mstpDevice"] = 1
                else:
                    device_metrics["remoteNetworkDevice"] = 1

            # Find all addresses that might be associated with this device
            for addr, dev_info in self.device_cache.items():
                if dev_info.device_id == device_id and addr in self.address_stats:
                    stats = self.address_stats[addr]

                    # Update metrics only if we found valid stats for this address
                    self._update_device_metrics(device_metrics, stats)

        # Now process metrics for interfaces without device IDs (using just the address)
        for addr, stats in self.address_stats.items():
            # Check if this address is already associated with a device
            is_associated = False
            for device_id, data in self.device_metrics.items():
                if isinstance(device_id, int):  # Skip address-based entries
                    for dev_addr, dev_info in self.device_cache.items():
                        if dev_info.device_id == device_id and addr == dev_addr:
                            is_associated = True
                            break

            # If not associated with a device, create an interface-based entry
            if not is_associated and not addr.startswith("device:"):
                # Create a unique "address ID" for this interface
                addr_id = f"addr_{addr.replace(':', '_')}"

                # Get address components and type
                network, mac, address_type, is_mstp = self._get_address_type(addr)

                metrics = self._initialize_metrics()

                # Set appropriate device type marker based on address type
                if is_mstp:
                    if address_type == "mstp":
                        metrics["mstpDevice"] = 1
                    else:
                        metrics["remoteNetworkDevice"] = 1

                # Create the device metrics entry
                self.device_metrics[addr_id] = {
                    "info": {
                        "address": addr,  # Store the address for display
                        "bacnet_address": addr,  # Use the address as the bacnet_address
                    },
                    "metrics": metrics,
                }

                # Update metrics for this interface
                self._update_device_metrics(self.device_metrics[addr_id]["metrics"], stats)

    def _update_device_metrics(self, device_metrics: Dict[str, int], stats: AddressStats) -> None:
        """Update device metrics from the given stats.

        Args:
            device_metrics: The metrics dictionary to update
            stats: The address stats to extract metrics from
        """
        # Network interface metrics - packets we've observed from this device
        device_metrics["packetsReceived"] += stats.total_packets
        device_metrics["totalBacnetMessagesSent"] += stats.total_packets

        # Count broadcast messages
        if stats.broadcast_messages > 0:
            device_metrics["broadcastPacketsSent"] += stats.broadcast_messages
            device_metrics["totalBroadcastsSent"] += stats.broadcast_messages
            device_metrics["globalBroadcastMessageCount"] += stats.broadcast_messages

        # Count total requests and responses
        total_requests = 0
        total_responses = 0

        # Application metrics based on message types
        if "WhoIsRequest" in stats.message_types:
            count = stats.message_types["WhoIsRequest"]
            device_metrics["whoIsRequestsSent"] += count
            device_metrics["globalWhoIsRequestsSent"] += count
            total_requests += count

        if "IAmRequest" in stats.message_types:
            count = stats.message_types["IAmRequest"]
            device_metrics["iAmResponsesSent"] += count
            total_responses += count

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

        # Handle ReadProperty requests and responses
        if "ReadPropertyRequest" in stats.message_types:
            count = stats.message_types["ReadPropertyRequest"]
            device_metrics["readPropertyRequestsSent"] += count
            total_requests += count

        if "ReadPropertyACK" in stats.message_types:
            count = stats.message_types["ReadPropertyACK"]
            device_metrics["readPropertyResponsesSent"] += count
            total_responses += count

        # Handle WriteProperty requests and responses
        if "WritePropertyRequest" in stats.message_types:
            count = stats.message_types["WritePropertyRequest"]
            device_metrics["writePropertyRequestsSent"] += count
            total_requests += count

        if "WritePropertyACK" in stats.message_types:
            count = stats.message_types["WritePropertyACK"]
            device_metrics["writePropertyResponsesSent"] += count
            total_responses += count

        # Handle COV notifications
        if "ConfirmedCOVNotificationRequest" in stats.message_types:
            count = stats.message_types["ConfirmedCOVNotificationRequest"]
            device_metrics["confirmedCOVNotificationsSent"] += count
            total_requests += count

        if "UnconfirmedCOVNotificationRequest" in stats.message_types:
            count = stats.message_types["UnconfirmedCOVNotificationRequest"]
            device_metrics["unconfirmedCOVNotificationsSent"] += count
            total_requests += count

        # Update total request and response counts
        device_metrics["totalRequestsSent"] += total_requests
        device_metrics["totalResponsesSent"] += total_responses

        # Router metrics
        if stats.routed_messages > 0:
            device_metrics["routedMessagesSent"] += stats.routed_messages
            device_metrics["messagesRouted"] += stats.routed_messages

            # For devices that route messages, estimate unique devices seen
            # This is an estimate - in a real implementation, we would track actual devices
            device_metrics["routedDevicesSeen"] = max(
                device_metrics["routedDevicesSeen"], int(stats.routed_messages / 10)
            )

        if stats.forwarded_packets > 0:
            device_metrics["broadcastRelayed"] += stats.forwarded_packets
            device_metrics["messagesForwarded"] += stats.forwarded_packets

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

    def _initialize_metrics(self) -> Dict[str, int]:
        """Initialize a metrics dictionary with zero values."""
        return defaultdict(
            int,
            {
                # Network interface metrics - only observed Sent operations
                "packetsReceived": 0,  # Count of packets observed, not actual reception
                "totalBacnetMessagesSent": 0,  # Total BACnet messages observed from this device
                "broadcastPacketsSent": 0,  # Broadcast packets observed from this device
                # Router metrics
                "routedMessagesSent": 0,  # Messages sent from this device via routing
                "broadcastRelayed": 0,  # Broadcasts relayed by this device
                "messagesRouted": 0,  # Messages routed by this device
                "messagesForwarded": 0,  # Messages forwarded by this device (BBMD)
                "routedDevicesSeen": 0,  # Number of unique devices seen through routing
                # WhoIs/IAm metrics
                "whoIsRequestsSent": 0,  # WhoIs requests sent by this device
                "globalWhoIsRequestsSent": 0,  # Global WhoIs requests sent by this device
                "directedWhoIsRequestsSent": 0,  # Directed WhoIs requests sent by this device
                "iAmResponsesSent": 0,  # IAm responses sent by this device
                # WhoHas/IHave metrics
                "whoHasRequestsSent": 0,  # WhoHas requests sent by this device
                "globalWhoHasRequestsSent": 0,  # Global WhoHas requests sent by this device
                "directedWhoHasRequestsSent": 0,  # Directed WhoHas requests sent by this device
                "iHaveResponsesSent": 0,  # IHave responses sent by this device
                # ReadProperty metrics
                "readPropertyRequestsSent": 0,  # ReadProperty requests sent by this device
                "readPropertyResponsesSent": 0,  # ReadProperty responses sent by this device
                # WriteProperty metrics
                "writePropertyRequestsSent": 0,  # WriteProperty requests sent by this device
                "writePropertyResponsesSent": 0,  # WriteProperty responses sent by this device
                # COV metrics
                "unconfirmedCOVNotificationsSent": 0,  # Unconfirmed COV notifications sent by this device
                "confirmedCOVNotificationsSent": 0,  # Confirmed COV notifications sent by this device
                # Global broadcast metrics
                "globalBroadcastMessageCount": 0,  # Count of global broadcasts from this device
                "totalBroadcastsSent": 0,  # Total broadcasts sent from this device
                # Application metrics
                "totalRequestsSent": 0,  # Total requests sent by this device
                "totalResponsesSent": 0,  # Total responses sent by this device
                # Device type markers
                "mstpDevice": 0,  # Whether this is an MS/TP device
                "remoteNetworkDevice": 0,  # Whether this is a device on a remote network
            },
        )

    def _build_rdf_graph(self) -> None:
        """Build the RDF graph from collected metrics."""
        # Add capture device if specified
        capture_device_uri = None
        if self.capture_device:
            # Create a URI for the capture device - clean up address for URI-friendliness
            clean_address = self.capture_device.replace(":", "_").replace(".", "_")
            capture_device_uri = self.EX[f"capture_{clean_address}"]

            # Add the capture device to the graph
            self.graph.add((capture_device_uri, RDF.type, self.CORONA.CaptureDevice))
            self.graph.add(
                (
                    capture_device_uri,
                    self.CORONA.identifier,
                    Literal("capture-device", datatype=XSD.string),
                )
            )
            self.graph.add(
                (
                    capture_device_uri,
                    self.CORONA.name,
                    Literal("BACnet Network Capture Device", datatype=XSD.string),
                )
            )
            self.graph.add(
                (
                    capture_device_uri,
                    self.CORONA.description,
                    Literal("Device used to capture BACnet traffic", datatype=XSD.string),
                )
            )
            self.graph.add(
                (
                    capture_device_uri,
                    self.BACNET.address,
                    Literal(self.capture_device, datatype=XSD.string),
                )
            )

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

    def _add_device_to_graph(
        self, device_id: int, device_info: Any, metrics: Dict[str, int], capture_device_uri=None
    ) -> None:
        """Add a BACnet device and its interface to the RDF graph.

        Args:
            device_id: The device ID
            device_info: The device information
            metrics: The metrics to add
            capture_device_uri: Optional URI of the capture device
        """
        # Determine address components
        bacnet_address_val: Optional[str] = getattr(device_info, 'bacnet_address', None)
        if not bacnet_address_val:  # Should not happen for a device with ID, but as a type guard
            return
        # Now bacnet_address_val is confirmed to be a string
        network, mac, address_type, is_mstp = self._get_address_type(bacnet_address_val)

        # Create URIs for device and interface
        device_uri = self.EX[f"dev-{device_id}"]
        interface_uri = self.EX[f"npm-{device_id}-if0"]

        # Add device triples
        self.graph.add((device_uri, RDF.type, self.BACNET.Device))
        self.graph.add(
            (
                device_uri,
                self.BACNET["object-identifier"],
                Literal(f"device,{device_id}", datatype=XSD.string),
            )
        )
        self.graph.add(
            (
                device_uri,
                self.BACNET["object-name"],
                Literal(f"BACnet Device {device_id}", datatype=XSD.string),
            )
        )

        # Add vendor ID if available
        if hasattr(device_info, "vendor_id") and device_info.vendor_id is not None:
            self.graph.add(
                (
                    device_uri,
                    self.BACNET["vendor-identifier"],
                    Literal(str(device_info.vendor_id), datatype=XSD.unsignedInt),
                )
            )

        # Add address information
        if hasattr(device_info, "bacnet_address"):
            self.graph.add(
                (
                    device_uri,
                    self.BACNET.address,
                    Literal(device_info.bacnet_address, datatype=XSD.string),
                )
            )

            # Add network number and MAC address if this is from a non-local network
            if network != "0":
                self.graph.add(
                    (
                        device_uri,
                        self.BACNET["network-number"],
                        Literal(network, datatype=XSD.unsignedInt),
                    )
                )

                # Format MAC address appropriately
                if address_type == "mstp":
                    try:
                        # Convert hex MAC to integer (removing leading zeros)
                        mac_int = int(mac, 16)
                        self.graph.add(
                            (
                                device_uri,
                                self.BACNET["mac-address"],
                                Literal(str(mac_int), datatype=XSD.unsignedInt),
                            )
                        )
                    except ValueError:
                        # If conversion fails, use the original string
                        self.graph.add(
                            (
                                device_uri,
                                self.BACNET["mac-address"],
                                Literal(mac, datatype=XSD.string),
                            )
                        )
                else:
                    # Use the original format for other networks
                    self.graph.add(
                        (
                            device_uri,
                            self.BACNET["mac-address"],
                            Literal(mac, datatype=XSD.string),
                        )
                    )

                # Add address type
                address_type_value = "ms-tp" if address_type == "mstp" else "remote-network"
                self.graph.add(
                    (
                        device_uri,
                        self.BACNET["address-type"],
                        Literal(address_type_value, datatype=XSD.string),
                    )
                )
            else:
                # For BACnet/IP devices
                self.graph.add(
                    (
                        device_uri,
                        self.BACNET["address-type"],
                        Literal("bacnet-ip", datatype=XSD.string),
                    )
                )

        # Link device to its interface
        self.graph.add((device_uri, self.BACNET.contains, interface_uri))

        # Add interface metrics
        self.graph.add((interface_uri, RDF.type, self.CORONA.NetworkInterfaceMetric))
        self.graph.add((interface_uri, RDF.type, self.CORONA.ApplicationMetric))

        # Add interface properties
        self.graph.add(
            (
                interface_uri,
                self.CORONA.identifier,
                Literal(f"network-performance-monitor-{device_id}", datatype=XSD.string),
            )
        )
        self.graph.add(
            (
                interface_uri,
                self.CORONA.name,
                Literal("Interface Performance Metrics", datatype=XSD.string),
            )
        )
        self.graph.add(
            (
                interface_uri,
                self.CORONA.description,
                Literal("Performance metrics from PCAP analysis.", datatype=XSD.string),
            )
        )

        # Relationship to parent device is handled by the BACNET.contains property

        # Add observedFrom relationship if capture_device provided
        if capture_device_uri:
            self.graph.add((interface_uri, self.CORONA.observedFrom, capture_device_uri))

        # Add all metrics with non-zero values
        for metric_name, value in metrics.items():
            if value > 0:  # Only include non-zero metrics
                self.graph.add(
                    (
                        interface_uri,
                        self.CORONA[metric_name],
                        Literal(str(value), datatype=XSD.unsignedLong),
                    )
                )

    def _add_interface_to_graph(
        self,
        interface_key: str,
        interface_info: Any,
        metrics: Dict[str, int],
        capture_device_uri=None,
    ) -> None:
        """Add an interface-only entry to the RDF graph.

        Args:
            interface_key: The interface key
            interface_info: The interface information
            metrics: The metrics to add
            capture_device_uri: Optional URI of the capture device
        """
        # Extract the address from the key
        address = interface_info.get("bacnet_address", "")
        if not address:
            address = interface_key.replace("addr_", "").replace("_", ":")

        # Parse address components
        network, mac, address_type, is_mstp = self._get_address_type(address)

        # Create URI for the interface
        interface_uri = self.EX[interface_key]

        # Determine interface type based on address
        interface_type = "BACnet/IP"
        if address_type == "mstp":
            interface_type = "BACnet MS/TP"
        elif address_type == "network":
            interface_type = "BACnet Network"

        # Add interface triples
        self.graph.add((interface_uri, RDF.type, self.CORONA.NetworkInterfaceMetric))
        self.graph.add((interface_uri, RDF.type, self.CORONA.ApplicationMetric))

        # Add interface properties
        self.graph.add(
            (
                interface_uri,
                self.CORONA.identifier,
                Literal(f"interface-{address.replace(':', '-')}", datatype=XSD.string),
            )
        )
        self.graph.add(
            (
                interface_uri,
                self.CORONA.name,
                Literal(f"{interface_type} Interface {address}", datatype=XSD.string),
            )
        )
        self.graph.add(
            (
                interface_uri,
                self.CORONA.description,
                Literal(
                    f"{interface_type} interface metrics for address {address}",
                    datatype=XSD.string,
                ),
            )
        )

        # Add address information
        self.graph.add((interface_uri, self.BACNET.address, Literal(address, datatype=XSD.string)))

        # Add more specific network information if available
        if network != "0":
            self.graph.add(
                (
                    interface_uri,
                    self.BACNET["network-number"],
                    Literal(network, datatype=XSD.unsignedInt),
                )
            )

            # Format MAC address appropriately
            if address_type == "mstp":
                try:
                    # Convert hex MAC to integer (removing leading zeros)
                    mac_int = int(mac, 16)
                    self.graph.add(
                        (
                            interface_uri,
                            self.BACNET["mac-address"],
                            Literal(str(mac_int), datatype=XSD.unsignedInt),
                        )
                    )
                except ValueError:
                    # If conversion fails, use the original string
                    self.graph.add(
                        (
                            interface_uri,
                            self.BACNET["mac-address"],
                            Literal(mac, datatype=XSD.string),
                        )
                    )
            else:
                # Use the original format for other networks
                self.graph.add(
                    (
                        interface_uri,
                        self.BACNET["mac-address"],
                        Literal(mac, datatype=XSD.string),
                    )
                )

            # Add address type
            address_type_value = "ms-tp" if address_type == "mstp" else "remote-network"
            self.graph.add(
                (
                    interface_uri,
                    self.BACNET["address-type"],
                    Literal(address_type_value, datatype=XSD.string),
                )
            )
        else:
            # For BACnet/IP devices
            self.graph.add(
                (
                    interface_uri,
                    self.BACNET["address-type"],
                    Literal("bacnet-ip", datatype=XSD.string),
                )
            )

        # Interface-only entries don't need a reportedBy relation

        # Add observedFrom relationship if capture device provided
        if capture_device_uri:
            self.graph.add((interface_uri, self.CORONA.observedFrom, capture_device_uri))

        # Add all metrics with non-zero values
        for metric_name, value in metrics.items():
            if value > 0:  # Only include non-zero metrics
                self.graph.add(
                    (
                        interface_uri,
                        self.CORONA[metric_name],
                        Literal(str(value), datatype=XSD.unsignedLong),
                    )
                )

    def export_ttl(self, output_file: str) -> None:
        """Export the metrics in Corona-compatible Turtle (.ttl) format.

        Args:
            output_file: The path to write the output file to
        """
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
            
    def export_haystack_zinc(self, output_file: str) -> None:
        """Export the metrics in Project Haystack Zinc Grid format.
        
        Args:
            output_file: The path to write the output file to
        """
        # Grid version and metadata
        timestamp = datetime.datetime.now().isoformat(timespec='seconds')
        grid = hszinc.Grid(version="3.0")
        grid.metadata.update({
            "database": "bacnet",
            "generatedOn": timestamp,
            "dis": "BACnet Corona Metrics"
        })

        # Define columns
        grid.column["id"] = {"dis": "ID"}
        grid.column["dis"] = {"dis": "Device"}
        grid.column["device"] = {}
        grid.column["deviceId"] = {}
        grid.column["bacnetAddress"] = {}
        grid.column["network"] = {}
        grid.column["mac"] = {}
        grid.column["addressType"] = {}
        grid.column["metric"] = {"dis": "Metric"}
        grid.column["val"] = {"dis": "Value"}
        grid.column["unit"] = {}
        
        # Iterate through all device and interface metrics
        for device_key, data in self.device_metrics.items():
            device_info = data["info"]
            metrics = data["metrics"]
            
            # Extract device information
            device_id_val = None
            device_name = None
            bacnet_address = device_info.get("bacnet_address") if isinstance(device_info, dict) else getattr(device_info, "bacnet_address", None)

            if isinstance(device_key, int):
                # This is a device with an ID
                device_id_val = device_key
                device_name = f"BACnet Device {device_id_val}"
            else:
                # This is an interface-only entry
                if isinstance(device_info, dict) and "address" in device_info:
                    bacnet_address = device_info["address"]
                elif hasattr(device_info, "address"):
                    bacnet_address = getattr(device_info, "address", None)
                
                device_name = f"Interface {bacnet_address}"
            
            if not bacnet_address:  # Skip if bacnet_address is None
                continue

            # Get address components
            network, mac, address_type, _ = self._get_address_type(bacnet_address)
            
            # Map address type to haystack value
            if address_type == "ip":
                haystack_address_type = "bacnet-ip"
            elif address_type == "mstp":
                haystack_address_type = "ms-tp"
            else:
                haystack_address_type = "remote-network"
            
            # Generate unique ID for each entity
            entity_id_str = f"{device_key}" if isinstance(device_key, str) else f"dev-{device_id_val}"
            
            # Add each metric as a separate row
            for metric_name, value in metrics.items():
                if value > 0:  # Only include non-zero metrics
                    row = {
                        "id": hszinc.Ref(entity_id_str),
                        "dis": device_name,
                        "device": hszinc.MARKER,
                        "deviceId": str(device_id_val) if device_id_val is not None else None,
                        "bacnetAddress": bacnet_address,
                        "network": network,
                        "mac": mac,
                        "addressType": haystack_address_type,
                        "metric": metric_name,
                        "val": value
                        # "unit": None # No units for these metrics yet, can be added if available
                    }
                    grid.append(row)
        
        # Write the file
        with open(output_file, "w", encoding='utf-8') as f:
            f.write(hszinc.dump(grid, mode=hszinc.MODE_ZINC))
            
    def export_haystack_json(self, output_file: str) -> None:
        """Export the metrics in Project Haystack JSON format.
        
        Args:
            output_file: The path to write the output file to
        """
        import json
        
        # Create the grid structure
        grid_meta: Dict[str, Any] = {
            "ver": "3.0",
            "database": "bacnet", 
            "generatedOn": datetime.datetime.now().isoformat(timespec='seconds'),
            "dis": "BACnet Corona Metrics"
        }
        grid_cols: List[Dict[str, str]] = [
            {"name": "id", "dis": "ID"},
            {"name": "dis", "dis": "Device"},
            {"name": "device"}, # No dis needed if name is the display name
            {"name": "deviceId"},
            {"name": "bacnetAddress"},
            {"name": "network"},
            {"name": "mac"},
            {"name": "addressType"},
            {"name": "metric", "dis": "Metric"},
            {"name": "val", "dis": "Value"},
            {"name": "unit"}
        ]
        grid_rows: List[Dict[str, Any]] = []

        grid: Dict[str, Any] = {
            "meta": grid_meta,
            "cols": grid_cols,
            "rows": grid_rows
        }
        
        # Iterate through all device and interface metrics
        for device_key, data in self.device_metrics.items():
            device_info = data["info"]
            metrics = data["metrics"]
            
            # Extract device information
            device_id = None
            device_name = None
            bacnet_address = device_info.bacnet_address if hasattr(device_info, "bacnet_address") else None
            
            if isinstance(device_key, int):
                # This is a device with an ID
                device_id = device_key
                device_name = f"BACnet Device {device_id}"
            else:
                # This is an interface-only entry
                if hasattr(device_info, "address"):
                    bacnet_address = device_info.address
                elif isinstance(device_info, dict) and "address" in device_info:
                    bacnet_address = device_info["address"]
                
                device_name = f"Interface {bacnet_address}"
            
            if not bacnet_address:  # Skip if bacnet_address is None
                continue

            # Get address components
            network, mac, address_type, _ = self._get_address_type(bacnet_address)
            
            # Map address type to haystack value
            if address_type == "ip":
                haystack_address_type = "bacnet-ip"
            elif address_type == "mstp":
                haystack_address_type = "ms-tp"
            else:
                haystack_address_type = "remote-network"
            
            # Generate unique ID for each entity
            entity_id = f"@{device_key}" if isinstance(device_key, str) else f"@dev-{device_id}"
            
            # Add each metric as a separate row
            for metric_name, value in metrics.items():
                if value > 0:  # Only include non-zero metrics
                    row_data: Dict[str, Any] = {
                        "id": {"_kind": "ref", "val": entity_id[1:]},  # Remove @ for JSON format
                        "dis": device_name,
                        "device": {"_kind": "marker"},
                        "deviceId": str(device_id) if device_id else None,
                        "bacnetAddress": bacnet_address,
                        "network": network,
                        "mac": mac,
                        "addressType": haystack_address_type,
                        "metric": metric_name,
                        "val": value,
                        "unit": None  # No units for these metrics yet
                    }
                    grid_rows.append(row_data)
        
        # Write the file
        with open(output_file, "w") as f:
            json.dump(grid, f, indent=2)
            
    def export_prometheus(self, output_file: str) -> None:
        """Export the metrics in Prometheus exposition format with OpenTelemetry semantic conventions.
        
        Args:
            output_file: The path to write the output file to
        """
        # Define metric prefix following OTel conventions
        prefix = "bacnet"
        
        # Define metric type mapping - based on the nature of the metric
        metric_types = {
            # Counters (metrics that only increase)
            "packetsReceived": "counter",
            "totalBacnetMessagesSent": "counter",
            "broadcastPacketsSent": "counter",
            "routedMessagesSent": "counter",
            "broadcastRelayed": "counter",
            "messagesRouted": "counter",
            "messagesForwarded": "counter",
            "whoIsRequestsSent": "counter",
            "globalWhoIsRequestsSent": "counter",
            "directedWhoIsRequestsSent": "counter",
            "iAmResponsesSent": "counter",
            "whoHasRequestsSent": "counter", 
            "globalWhoHasRequestsSent": "counter",
            "directedWhoHasRequestsSent": "counter",
            "iHaveResponsesSent": "counter",
            "readPropertyRequestsSent": "counter",
            "readPropertyResponsesSent": "counter",
            "writePropertyRequestsSent": "counter",
            "writePropertyResponsesSent": "counter",
            "unconfirmedCOVNotificationsSent": "counter",
            "confirmedCOVNotificationsSent": "counter",
            "globalBroadcastMessageCount": "counter",
            "totalBroadcastsSent": "counter",
            "totalRequestsSent": "counter",
            "totalResponsesSent": "counter",
            
            # Gauges (metrics that can go up or down)
            "routedDevicesSeen": "gauge",
            
            # Boolean indicators (0 or 1)
            "mstpDevice": "gauge",
            "remoteNetworkDevice": "gauge",
        }
        
        # Map our metrics to OTel convention metric names
        metric_name_map = {
            "packetsReceived": "packets_total",
            "totalBacnetMessagesSent": "messages_sent_total",
            "broadcastPacketsSent": "broadcast_packets_total",
            "routedMessagesSent": "routed_messages_total",
            "broadcastRelayed": "broadcast_relayed_total",
            "messagesRouted": "messages_routed_total",
            "messagesForwarded": "messages_forwarded_total",
            "routedDevicesSeen": "routed_devices",
            "whoIsRequestsSent": "whois_requests_total",
            "globalWhoIsRequestsSent": "global_whois_requests_total",
            "directedWhoIsRequestsSent": "directed_whois_requests_total",
            "iAmResponsesSent": "iam_responses_total",
            "whoHasRequestsSent": "whohas_requests_total",
            "globalWhoHasRequestsSent": "global_whohas_requests_total",
            "directedWhoHasRequestsSent": "directed_whohas_requests_total",
            "iHaveResponsesSent": "ihave_responses_total",
            "readPropertyRequestsSent": "read_property_requests_total",
            "readPropertyResponsesSent": "read_property_responses_total",
            "writePropertyRequestsSent": "write_property_requests_total",
            "writePropertyResponsesSent": "write_property_responses_total",
            "unconfirmedCOVNotificationsSent": "unconfirmed_cov_notifications_total",
            "confirmedCOVNotificationsSent": "confirmed_cov_notifications_total",
            "globalBroadcastMessageCount": "global_broadcasts_total",
            "totalBroadcastsSent": "total_broadcasts_total",
            "totalRequestsSent": "total_requests_total",
            "totalResponsesSent": "total_responses_total",
            "mstpDevice": "is_mstp_device",
            "remoteNetworkDevice": "is_remote_network_device",
        }
        
        # Start writing the file with the current timestamp
        with open(output_file, "w") as f:
            f.write(f"# BACnet metrics generated on {datetime.datetime.now().isoformat()}\n")
            f.write("# This file follows Prometheus exposition format and OpenTelemetry semantic conventions\n\n")
            
            # Process each metric by type for all devices
            processed_metrics = {}
            
            # First, create HELP and TYPE entries for each metric
            for metric_name, prometheus_name in metric_name_map.items():
                full_metric_name = f"{prefix}_{prometheus_name}"
                metric_type = metric_types.get(metric_name, "untyped")
                
                help_text = self._get_metric_help_text(metric_name)
                metric_values_list: List[str] = []  # Explicitly define as List[str]
                processed_metrics[metric_name] = {
                    "name": full_metric_name,
                    "type": metric_type,
                    "help": help_text,
                    "values": metric_values_list  # Assign the typed list
                }
                
                # Write HELP and TYPE comments
                f.write(f"# HELP {full_metric_name} {help_text}\n")
                f.write(f"# TYPE {full_metric_name} {metric_type}\n")
            
            # Now collect actual values for each metric
            for device_key, data in self.device_metrics.items():
                device_info = data["info"]
                metrics = data["metrics"]
                
                # Extract device information
                device_id_val = None
                device_name = None
                bacnet_address = device_info.get("bacnet_address") if isinstance(device_info, dict) else getattr(device_info, "bacnet_address", None)
                
                if isinstance(device_key, int):
                    # This is a device with an ID
                    device_id_val = device_key
                    device_name = f"Device {device_id_val}"
                else:
                    # This is an interface-only entry
                    if isinstance(device_info, dict) and "address" in device_info:
                        bacnet_address = device_info["address"]
                    elif hasattr(device_info, "address"):
                        bacnet_address = getattr(device_info, "address", None)
                    
                    device_name = f"Interface {bacnet_address}"

                if not bacnet_address:  # Skip if bacnet_address is None
                    continue
                
                # Get address components
                network, mac, address_type, is_mstp = self._get_address_type(bacnet_address)
                
                # Define base labels for this device
                base_labels = {
                    "device_id": str(device_id_val) if device_id_val else "",
                    "address": bacnet_address if bacnet_address else "",
                    "network": network if network else "0",
                    "name": device_name,
                }
                
                # Add address type as a label
                if address_type == "ip":
                    base_labels["address_type"] = "bacnet_ip"
                elif address_type == "mstp":
                    base_labels["address_type"] = "mstp"
                else:
                    base_labels["address_type"] = "remote_network"
                
                # Add each metric value for this device
                for metric_name, value in metrics.items():
                    if value > 0 and metric_name in metric_name_map:  # Only include non-zero metrics
                        metric_data = processed_metrics[metric_name]
                        # Ensure type checker knows metric_data["name"] is str
                        current_prometheus_name: str = str(metric_data["name"])
                        
                        # Format labels according to Prometheus conventions
                        label_str = ",".join([f'{k}="{v}"' for k, v in base_labels.items()])
                        if label_str:
                            metric_line = f'{current_prometheus_name}{{{label_str}}} {value}'
                        else:
                            metric_line = f'{current_prometheus_name} {value}'
                        
                        # Ensure type checker knows metric_data["values"] is List[str]
                        cast(List[str], metric_data["values"]).append(metric_line)
            
            # Write all the metric values 
            for metric_info in processed_metrics.values():
                # Skip metrics with no values
                if not metric_info["values"]:
                    continue
                    
                # Write values for this metric
                for value_line in metric_info["values"]:
                    f.write(f"{value_line}\n")
                
                # Add blank line between different metrics for readability
                f.write("\n")
    
    def _get_metric_help_text(self, metric_name: str) -> str:
        """Get help text for a metric.
        
        Args:
            metric_name: The name of the metric
            
        Returns:
            A string with help text describing the metric
        """
        help_texts = {
            "packetsReceived": "Total number of BACnet packets observed from this device",
            "totalBacnetMessagesSent": "Total number of BACnet messages sent by this device",
            "broadcastPacketsSent": "Number of broadcast packets sent by this device",
            "routedMessagesSent": "Number of messages sent via routing by this device",
            "broadcastRelayed": "Number of broadcasts relayed by this device",
            "messagesRouted": "Number of messages routed by this device",
            "messagesForwarded": "Number of messages forwarded by this device (BBMD)",
            "routedDevicesSeen": "Number of unique devices seen through routing",
            "whoIsRequestsSent": "Number of WhoIs requests sent by this device",
            "globalWhoIsRequestsSent": "Number of global WhoIs requests sent by this device",
            "directedWhoIsRequestsSent": "Number of directed WhoIs requests sent by this device",
            "iAmResponsesSent": "Number of IAm responses sent by this device",
            "whoHasRequestsSent": "Number of WhoHas requests sent by this device",
            "globalWhoHasRequestsSent": "Number of global WhoHas requests sent by this device",
            "directedWhoHasRequestsSent": "Number of directed WhoHas requests sent by this device",
            "iHaveResponsesSent": "Number of IHave responses sent by this device",
            "readPropertyRequestsSent": "Number of ReadProperty requests sent by this device",
            "readPropertyResponsesSent": "Number of ReadProperty responses sent by this device",
            "writePropertyRequestsSent": "Number of WriteProperty requests sent by this device",
            "writePropertyResponsesSent": "Number of WriteProperty responses sent by this device",
            "unconfirmedCOVNotificationsSent": "Number of unconfirmed COV notifications sent by this device",
            "confirmedCOVNotificationsSent": "Number of confirmed COV notifications sent by this device",
            "globalBroadcastMessageCount": "Count of global broadcasts from this device",
            "totalBroadcastsSent": "Total number of broadcasts sent by this device",
            "totalRequestsSent": "Total number of BACnet requests sent by this device",
            "totalResponsesSent": "Total number of BACnet responses sent by this device",
            "mstpDevice": "Indicates if this is an MS/TP device (1=yes, 0=no)",
            "remoteNetworkDevice": "Indicates if this is a device on a remote network (1=yes, 0=no)",
        }
        
        return help_texts.get(metric_name, f"Metric {metric_name} from BACnet device")
