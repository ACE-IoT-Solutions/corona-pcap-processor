"""
Main BACnet PCAP Analyzer implementation.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from bacpypes3.analysis import decode_file, decode_packet, settings
from bacpypes3.apdu import apdu_types
from bacpypes3.basetypes import Address

from .constants import SERVICE_CHOICE_TO_TYPE, ServiceChoiceMapping, ServiceChoice
from .debug_utils import debug_frame
from .device_catalog import add_device_to_catalog, get_device_key
from .models import AddressStats, AnalysisResults, DeviceInfo
from .packet_processors import (
    extract_apdu_type,
    extract_device_id,
    extract_device_info,
    extract_frame_timestamp,
    extract_network_and_mac,
    extract_service_choice,
    extract_source_dest_addresses,
    is_bacnet_ip_packet,
)
from .reporting import generate_full_report, print_report
from .stats_collector import create_empty_stats, update_stats_dict

# Enable route awareness in BACpypes3
settings.route_aware = True


class BACnetAnalyzer:
    """BACnet PCAP Analyzer using a functional approach."""
    
    def __init__(self, debug: bool = False, debug_level: int = 1):
        """Initialize the analyzer.
        
        Args:
            debug: Whether to enable debug mode
            debug_level: Debug verbosity level (1-3)
        """
        self.debug = debug
        self.debug_level = debug_level
        self.logger = logging.getLogger("BACnetAnalyzer")
        
        if debug:
            self.logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            self.logger.addHandler(handler)
        else:
            self.logger.setLevel(logging.WARNING)
    
    def analyze_pcap(self, filepath: str) -> AnalysisResults:
        """Analyze a PCAP file and extract BACnet information.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            Analysis results containing statistics and device information
        """
        # Initialize empty results
        results = AnalysisResults()
        
        # Process each frame in the PCAP file
        for frame in decode_file(filepath):
            # Process the frame and update results
            results = self._process_frame(frame, results)
        
        return results
    
    def _process_frame(self, frame: any, results: AnalysisResults) -> AnalysisResults:
        """Process a BACnet frame and update the analysis results.
        
        Args:
            frame: The BACnet frame to process
            results: The current analysis results
            
        Returns:
            Updated analysis results
        """
        # Print debug information if enabled
        if self.debug:
            for msg in debug_frame(frame, self.debug_level):
                self.logger.debug(msg)
        
        # Extract packet timestamp
        pkt_time = extract_frame_timestamp(frame)
        
        # Extract source and destination addresses
        ip_src, ip_dst, is_broadcast = extract_source_dest_addresses(frame)
        
        # Skip if not a valid BACnet packet
        if not ip_src:
            return results
        
        # Create mutable copies of the result collections for updating
        address_stats = results.address_stats.copy()
        device_cache = results.device_cache.copy()
        
        # Handle BACnet/IP packets
        if is_bacnet_ip_packet(frame):
            # Track basic BACnet/IP stats
            address_stats = update_stats_dict(
                address_stats,
                ip_src,
                "BACnet/IP",
                is_broadcast=is_broadcast,
            )
            
            # Check if this is a forwarded NPDU from a router/BBMD
            if hasattr(frame, "bvll") and frame.bvll:
                bvll_type = type(frame.bvll).__name__
                
                # Update stats for the BVLL type
                address_stats = update_stats_dict(
                    address_stats,
                    ip_src,
                    bvll_type,
                    is_broadcast=is_broadcast,
                )
                
                # Handle forwarded NPDU specifically
                if bvll_type == "ForwardedNPDU":
                    # Process the forwarded NPDU
                    results = self._process_forwarded_npdu(
                        frame.bvll, ip_src, ip_dst, pkt_time, results
                    )
            
            # Process direct APDU if present
            if hasattr(frame, "apdu") and frame.apdu:
                # Get the NPDU if available for address extraction
                npdu = frame.npdu if hasattr(frame, "npdu") else None
                
                # Get the APDU type
                apdu_type = extract_apdu_type(frame.apdu)
                
                # Update stats for the APDU type
                address_stats = update_stats_dict(
                    address_stats,
                    ip_src,
                    apdu_type,
                    is_broadcast=is_broadcast,
                )
                
                # Check for service choice and add as separate entry
                service_choice = extract_service_choice(frame.apdu)
                if service_choice is not None:
                    service_type = ServiceChoiceMapping.get_message_type(service_choice)
                    
                    if service_type and service_type != apdu_type:
                        # Only add if different from the original class name
                        address_stats = update_stats_dict(
                            address_stats,
                            ip_src,
                            service_type,
                            is_broadcast=is_broadcast,
                        )
                        
                        if self.debug and service_choice == ServiceChoice.WHO_HAS.value:
                            self.logger.debug(
                                f"Found WhoHas message (service 7) in {apdu_type} from {ip_src}"
                            )
                
                # Process I-Am requests specially to extract device info
                if apdu_type == "IAmRequest":
                    # Extract network and MAC from NPDU if available
                    network, mac = extract_network_and_mac(npdu)
                    
                    # Generate device key
                    device_key, key_type = get_device_key(network, mac, ip_src)
                    
                    # Extract device info
                    device_info = extract_device_info(
                        frame.apdu, ip_src, pkt_time, device_key, is_forwarded=False
                    )
                    
                    # Add to device cache if valid
                    if device_info:
                        device_cache = add_device_to_catalog(device_cache, device_info)
                        
                        if self.debug:
                            self.logger.debug(
                                f"Added device {device_info.device_id} with {key_type} {device_key}"
                            )
        
        # Create updated results
        updated_results = AnalysisResults(
            address_stats=address_stats,
            device_cache=device_cache,
        )
        
        return updated_results
    
    def _process_forwarded_npdu(
        self, 
        bvll: any, 
        source_ip: str, 
        destination_ip: str, 
        pkt_time: float, 
        results: AnalysisResults
    ) -> AnalysisResults:
        """Process a forwarded NPDU message from a BACnet router/BBMD.
        
        Args:
            bvll: The BVLL layer containing the forwarded NPDU
            source_ip: The IP address of the source
            destination_ip: The IP address of the destination
            pkt_time: The timestamp of the packet
            results: The current analysis results
            
        Returns:
            Updated analysis results
        """
        # Create mutable copies of the result collections
        address_stats = results.address_stats.copy()
        device_cache = results.device_cache.copy()
        
        # Get the forwarding router address
        router_addr = getattr(bvll, "bvlciAddress", None)
        router_addr_str = str(router_addr) if router_addr else None
        
        if not router_addr_str:
            if self.debug:
                self.logger.debug("Error: Forwarded NPDU without bvlciAddress")
            return results
        
        # Update forwarded packets count
        stats = address_stats.get(source_ip, create_empty_stats())
        stats.forwarded_packets += 1
        address_stats[source_ip] = stats
        
        # Initialize default values
        network = None
        mac = None
        
        # Extract info from NPDU if available
        if hasattr(bvll, "npdu") and bvll.npdu:
            npdu = bvll.npdu
            
            # Extract network and MAC
            network, mac = extract_network_and_mac(npdu)
            
            # Print debug info if enabled
            if self.debug and network is not None:
                self.logger.debug(f"Found BACnet source network: {network}")
                if mac is not None:
                    self.logger.debug(f"Found BACnet source MAC: {mac}")
                    self.logger.debug(f"Complete BACnet address: {network}:{mac}")
            
            # Process APDU in NPDU if available
            if hasattr(npdu, "apdu") and npdu.apdu:
                apdu = npdu.apdu
                apdu_type = extract_apdu_type(apdu)
                
                # Create a unique source identifier if we have network and MAC
                actual_source = None
                if network is not None and mac is not None:
                    actual_source = f"{network}:{mac}"
                    
                    # Update statistics for the actual device
                    address_stats = update_stats_dict(
                        address_stats,
                        actual_source,
                        apdu_type,
                        is_broadcast=destination_ip.endswith("255.255.255"),
                    )
                    
                    # Check for service choice and add as separate entry
                    service_choice = extract_service_choice(apdu)
                    if service_choice is not None:
                        service_type = ServiceChoiceMapping.get_message_type(service_choice)
                        
                        if service_type and service_type != apdu_type:
                            # Only add if different from the original class name
                            address_stats = update_stats_dict(
                                address_stats,
                                actual_source,
                                service_type,
                                is_broadcast=destination_ip.endswith("255.255.255"),
                            )
                            
                            if self.debug:
                                if service_choice in [1, 7]:  # IHave or WhoHas
                                    svc_name = "WhoHas" if service_choice == 7 else "IHave"
                                    self.logger.debug(
                                        f"Found {svc_name} message (service {service_choice}) from {actual_source}"
                                    )
                else:
                    # If we don't have network and MAC, update router stats
                    address_stats = update_stats_dict(
                        address_stats,
                        router_addr_str,
                        apdu_type,
                        is_broadcast=destination_ip.endswith("255.255.255"),
                    )
                    
                    # Check for service choice and add as separate entry
                    service_choice = extract_service_choice(apdu)
                    if service_choice is not None:
                        service_type = ServiceChoiceMapping.get_message_type(service_choice)
                        
                        if service_type and service_type != apdu_type:
                            # Only add if different from the original class name
                            address_stats = update_stats_dict(
                                address_stats,
                                router_addr_str,
                                service_type,
                                is_broadcast=destination_ip.endswith("255.255.255"),
                            )
                            
                            if self.debug:
                                if service_choice in [1, 7]:  # IHave or WhoHas
                                    svc_name = "WhoHas" if service_choice == 7 else "IHave"
                                    self.logger.debug(
                                        f"Found {svc_name} message (service {service_choice}) from {router_addr_str}"
                                    )
                
                # Process I-Am requests specially to extract device info
                if apdu_type == "IAmRequest":
                    # Generate device key
                    device_key, key_type = get_device_key(network, mac, router_addr_str)
                    
                    # Extract device info
                    device_info = extract_device_info(
                        apdu, router_addr_str, pkt_time, device_key, is_forwarded=True
                    )
                    
                    # Add to device cache if valid
                    if device_info:
                        device_cache = add_device_to_catalog(device_cache, device_info)
                        
                        if self.debug:
                            self.logger.debug(
                                f"Found I-Am in forwarded packet, via router {router_addr_str}"
                            )
        
        # Create updated results
        updated_results = AnalysisResults(
            address_stats=address_stats,
            device_cache=device_cache,
        )
        
        return updated_results
    
    def print_summary(self, results: AnalysisResults) -> None:
        """Print a summary of the analysis results.
        
        Args:
            results: The analysis results to summarize
        """
        report_lines = generate_full_report(results)
        print_report(report_lines)