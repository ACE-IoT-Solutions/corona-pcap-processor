#!/usr/bin/env python
"""
BACnet Corona Metrics Generator
Generates Corona-compatible metrics from BACnet PCAP analysis.
"""

import sys
import os
import datetime
from typing import Dict, List, Set, Any, Optional, Tuple
from collections import defaultdict

from main import BACnetPcapAnalyzer, DeviceInfo


class CoronaMetricsGenerator:
    """Generates Corona-compatible metrics from BACnet PCAP analysis."""
    
    def __init__(self, analyzer: BACnetPcapAnalyzer):
        """Initialize with a BACnetPcapAnalyzer instance."""
        self.analyzer = analyzer
        self.device_metrics = {}  # Will hold per-device metrics
        
    def generate_metrics(self) -> None:
        """Process analyzer data and generate metrics."""
        # First collect the device info from the analyzer
        self._collect_device_metrics()
        
    def _collect_device_metrics(self) -> None:
        """Extract metrics from the analyzer's device cache and address_stats."""
        # First, collect all devices by their ID
        device_id_map = {}
        for device_addr, device_info in self.analyzer.device_cache.items():
            device_id = device_info.device_id
            # Skip duplicate device:id entries
            if device_addr.startswith("device:"):
                continue
                
            device_id_map[device_id] = device_info
        
        # Process metrics for known devices with IDs
        for device_id, device_info in device_id_map.items():
            self.device_metrics[device_id] = {
                "info": device_info,
                "metrics": self._initialize_metrics()
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
            for addr, dev_info in self.analyzer.device_cache.items():
                if dev_info.device_id == device_id and addr in self.analyzer.address_stats:
                    stats = self.analyzer.address_stats[addr]
                    
                    # Update metrics only if we found valid stats for this address
                    self._update_device_metrics(device_metrics, stats)
        
        # Now process metrics for interfaces without device IDs (using just the address)
        for addr, stats in self.analyzer.address_stats.items():
            # Check if this address is already associated with a device
            is_associated = False
            for device_id, data in self.device_metrics.items():
                if isinstance(device_id, int):  # Skip address-based entries
                    for dev_addr, dev_info in self.analyzer.device_cache.items():
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
                        "bacnet_address": addr  # Use the address as the bacnet_address
                    },
                    "metrics": metrics
                }
                
                # Update metrics for this interface
                self._update_device_metrics(self.device_metrics[addr_id]["metrics"], stats)
    
    def _update_device_metrics(self, device_metrics, stats):
        """Update device metrics from the given stats."""
        # Network interface metrics
        device_metrics["packetsReceived"] += stats.total_packets
        device_metrics["broadcastPacketsReceived"] += stats.broadcast_messages
        
        # Count all BACnet messages
        device_metrics["totalBacnetMessagesSent"] += stats.total_packets
        
        # Count broadcast messages
        device_metrics["totalBroadcastsSent"] += stats.broadcast_messages
        device_metrics["globalBroadcastMessageCount"] += stats.broadcast_messages
        
        # Count total requests
        total_requests = 0
        successful_responses = 0
                
        # Application metrics based on message types
        if "WhoIsRequest" in stats.message_types:
            count = stats.message_types["WhoIsRequest"]
            device_metrics["whoIsRequestsSent"] += count
            device_metrics["globalWhoIsRequestsSent"] += count
            total_requests += count
        
        if "IAmRequest" in stats.message_types:
            count = stats.message_types["IAmRequest"]
            device_metrics["iAmResponsesSent"] += count
            successful_responses += count
        
        if "ReadPropertyRequest" in stats.message_types:
            count = stats.message_types["ReadPropertyRequest"]
            device_metrics["readPropertyRequestsSent"] += count
            device_metrics["readPropertyRequests"] += count
            total_requests += count
        
        if "ReadPropertyACK" in stats.message_types:
            count = stats.message_types["ReadPropertyACK"]
            device_metrics["readPropertyResponsesSent"] += count
            device_metrics["readPropertyResponses"] += count
            successful_responses += count
        
        # Handle Who-Has if present
        if "WhoHasRequest" in stats.message_types:
            count = stats.message_types["WhoHasRequest"]
            device_metrics["globalWhoHasRequestsSent"] += count
            total_requests += count
        
        # Handle COV notifications if present
        if "ConfirmedCOVNotificationRequest" in stats.message_types:
            count = stats.message_types["ConfirmedCOVNotificationRequest"]
            device_metrics["confirmedCOVNotificationsSent"] += count
            total_requests += count
            
        if "UnconfirmedCOVNotificationRequest" in stats.message_types:
            count = stats.message_types["UnconfirmedCOVNotificationRequest"]
            device_metrics["unconfirmedCOVNotificationsSent"] += count
            total_requests += count
        
        # Update total request counts
        device_metrics["totalRequests"] += total_requests
        device_metrics["successfulResponses"] += successful_responses
        
        # Router metrics
        device_metrics["routedMessagesSent"] += stats.routed_messages
        device_metrics["messagesRouted"] += stats.routed_messages
        
        # For devices that route messages, count unique devices seen
        if stats.routed_messages > 0:
            # This is an estimate - in a real implementation, we would track actual devices
            device_metrics["routedDevicesSeen"] = max(device_metrics["routedDevicesSeen"], 
                                                     int(stats.routed_messages / 10))
        
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
        return defaultdict(int, {
            # Network interface metrics
            "bytesReceived": 0,
            "bytesSent": 0,
            "packetsReceived": 0,
            "packetsSent": 0,
            "broadcastPacketsReceived": 0,
            "broadcastPacketsSent": 0,
            "errorPacketsReceived": 0,
            "packetsDroppedReceived": 0,
            
            # Router metrics
            "routedMessagesSent": 0,
            "routedMessagesReceived": 0,
            "broadcastRelayed": 0,
            "messagesRouted": 0,
            "messagesForwarded": 0,
            "routedDevicesSeen": 0,  # Number of unique devices seen through routing
            
            # WhoIs/IAm metrics
            "whoIsRequestsSent": 0,
            "whoIsRequestsReceived": 0,
            "globalWhoIsRequestsSent": 0,
            "directedWhoIsRequestsSent": 0,
            "iAmResponsesSent": 0,
            "iAmResponsesReceived": 0,
            
            # WhoHas metrics
            "globalWhoHasRequestsSent": 0,
            "directedWhoHasRequestsSent": 0,
            
            # ReadProperty metrics
            "readPropertyRequests": 0,
            "readPropertyResponses": 0,
            "readPropertyRequestsSent": 0,
            "readPropertyRequestsReceived": 0,
            "readPropertyResponsesSent": 0,
            "readPropertyResponsesReceived": 0,
            
            # COV metrics
            "unconfirmedCOVNotificationsSent": 0,
            "confirmedCOVNotificationsSent": 0,
            "unconfirmedCOVNotificationsReceived": 0,
            "confirmedCOVNotificationsReceived": 0,
            
            # Global broadcast metrics
            "globalBroadcastMessageCount": 0,
            "totalBacnetMessagesSent": 0,
            "totalBroadcastsSent": 0,
            
            # Application metrics  
            "totalRequests": 0,
            "successfulResponses": 0,
            "totalProperties": 0,
            
            # Device type markers
            "mstpDevice": 0,
            "remoteNetworkDevice": 0,
        })
    
    def export_ttl(self, output_file: str) -> None:
        """Export the metrics in Corona-compatible Turtle (.ttl) format."""
        # Get current timestamp for file generation
        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        with open(output_file, 'w') as f:
            # Write TTL header
            f.write(f"""# Corona BACnet metrics generated from PCAP analysis
# Generated on: {timestamp}

@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix bacnet: <https://data.ashrae.org/bacnet/> .
@prefix corona: <http://example.org/standards/corona/metrics#> .
@prefix ex: <http://example.org/bacnet-impl/> .

""")
            
            # Write device metrics
            for device_key, data in self.device_metrics.items():
                device_info = data["info"]
                metrics = data["metrics"]
                
                # Handle both device IDs and address-based entries
                if isinstance(device_key, int):
                    # This is a device with an ID
                    device_id = device_key
                    
                    # Determine the correct device address
                    bacnet_address = device_info.bacnet_address
                    network, mac, address_type, is_mstp = self._get_address_type(bacnet_address)
                    
                    # Create a device URI
                    device_uri = f"ex:dev-{device_id}"
                    interface_uri = f"ex:npm-{device_id}-if0"
                    
                    # Determine the device type based on address type
                    device_type_desc = "BACnet/IP Device"
                    if address_type == "mstp":
                        device_type_desc = "BACnet MS/TP Device"
                    elif address_type == "network":
                        device_type_desc = "BACnet Network Device"
                        
                    # Write device info
                    f.write(f"""# --- {device_type_desc} {device_id} ---
{device_uri}
    rdf:type bacnet:Device ;
    bacnet:object-identifier "device,{device_id}" ;
    bacnet:object-name "BACnet Device {device_id}" ;
""")
                    
                    if hasattr(device_info, 'vendor_id') and device_info.vendor_id is not None:
                        f.write(f"    bacnet:vendor-identifier {device_info.vendor_id} ;\n")
                    
                    # Add address information
                    if hasattr(device_info, 'bacnet_address'):
                        # Include the full BACnet address
                        f.write(f"    bacnet:address \"{device_info.bacnet_address}\" ;\n")
                        
                        # Add more specific network information
                        if network != "0":
                            f.write(f"    bacnet:network-number {network} ;\n")
                            f.write(f"    bacnet:mac-address \"{mac}\" ;\n")
                            
                            # Add address type information
                            if address_type == "mstp":
                                f.write(f"    bacnet:address-type \"ms-tp\" ;\n")
                            else:
                                f.write(f"    bacnet:address-type \"remote-network\" ;\n")
                        else:
                            # For BACnet/IP
                            f.write(f"    bacnet:address-type \"bacnet-ip\" ;\n")
                    
                    f.write(f"    bacnet:contains {interface_uri} .\n\n")
                    
                    # Write network interface metrics
                    f.write(f"""# --- Network Performance Monitor for {device_type_desc} {device_id} ---
{interface_uri}
    rdf:type bacnet:Object ;
    rdf:type corona:NetworkInterfaceMetric, corona:ApplicationMetric ;
    
    # Standard BACnet Properties
    bacnet:object-identifier "network-performance-monitor,1" ;
    bacnet:object-name "Interface Performance Metrics" ;
    bacnet:description "Performance metrics from PCAP analysis." ;
    
    # Corona properties
    corona:observedFrom {device_uri} ;
""")
                else:
                    # This is an address-based entry (no associated device ID)
                    # Extract the address from the key
                    address = device_key.replace('addr_', '').replace('_', ':')
                    
                    # Parse network and MAC address
                    network, mac, address_type, is_mstp = self._get_address_type(address)
                    
                    # Create URIs for the interface
                    interface_uri = f"ex:{device_key}"
                    
                    # Determine interface type based on address
                    interface_type = "BACnet/IP"
                    if address_type == "mstp":
                        interface_type = "BACnet MS/TP"
                    elif address_type == "network":
                        interface_type = "BACnet Network"
                    
                    # Write network interface metrics
                    f.write(f"""# --- {interface_type} Interface {address} ---
{interface_uri}
    rdf:type corona:NetworkInterfaceMetric, corona:ApplicationMetric ;
    
    # Interface Properties
    bacnet:address "{address}" ;
    bacnet:object-name "{interface_type} Interface {address}" ;
    bacnet:description "{interface_type} interface metrics for address {address}" ;
""")
                    
                    # Add more specific network information if available
                    if network != "0":
                        f.write(f"    bacnet:network-number {network} ;\n")
                        f.write(f"    bacnet:mac-address \"{mac}\" ;\n")
                        
                        # Add address type information
                        if address_type == "mstp":
                            f.write(f"    bacnet:address-type \"ms-tp\" ;\n")
                        else:
                            f.write(f"    bacnet:address-type \"remote-network\" ;\n")
                    else:
                        # For BACnet/IP
                        f.write(f"    bacnet:address-type \"bacnet-ip\" ;\n")
                    
                    f.write(f"""
    # Corona properties
    corona:observedFrom {interface_uri} ;
""")
                
                # Write actual metrics - for both device and interface entries
                for metric_name, value in metrics.items():
                    if value > 0:  # Only include non-zero metrics
                        f.write(f"    corona:{metric_name} \"{value}\"^^xsd:unsignedLong ;\n")
                
                # Replace the last semicolon with a period
                f.seek(f.tell() - 2, 0)
                f.write(" .\n\n")
    
    @staticmethod
    def process_pcap_and_generate_metrics(pcap_file: str, output_file: str, debug: bool = False) -> None:
        """Process a PCAP file and generate Corona metrics in one step."""
        analyzer = BACnetPcapAnalyzer(debug=debug)
        try:
            analyzer.process_pcap(pcap_file)
            metrics_gen = CoronaMetricsGenerator(analyzer)
            metrics_gen.generate_metrics()
            metrics_gen.export_ttl(output_file)
            print(f"Corona metrics exported to {output_file}")
        except Exception as e:
            print(f"Error generating metrics: {e}")
            import traceback
            traceback.print_exc()


def main():
    if len(sys.argv) < 3:
        print("Usage: python corona_metrics.py <pcap_file> <output_ttl_file> [--debug]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2]
    debug_mode = len(sys.argv) > 3 and sys.argv[3] == '--debug'
    
    CoronaMetricsGenerator.process_pcap_and_generate_metrics(pcap_file, output_file, debug_mode)


if __name__ == "__main__":
    main()