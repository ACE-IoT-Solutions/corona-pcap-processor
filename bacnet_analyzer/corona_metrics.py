"""
BACnet Corona Metrics Generator
Generates Corona-compatible metrics from BACnet PCAP analysis using rdflib.
This module works with the functional BACnetAnalyzer implementation.
"""

import datetime
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from rdflib import RDF, RDFS, XSD, Graph, Literal, Namespace, URIRef

from .models import AddressStats, AnalysisResults, DeviceInfo


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
        self.device_metrics = {}  # Will hold per-device metrics
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
        bacnet_address = device_info.bacnet_address
        network, mac, address_type, is_mstp = self._get_address_type(bacnet_address)

        # Create URIs for device and interface
        device_uri = self.EX[f"dev-{device_id}"]
        interface_uri = self.EX[f"npm-{device_id}-if0"]

        # Determine device type description
        device_type_desc = "BACnet/IP Device"
        if address_type == "mstp":
            device_type_desc = "BACnet MS/TP Device"
        elif address_type == "network":
            device_type_desc = "BACnet Network Device"

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
