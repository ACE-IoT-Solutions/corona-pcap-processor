#!/usr/bin/env python
"""
BACnet PCAP Analyzer
Analyzes and aggregates BACnet packet data from PCAP files.
"""

import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from typing import Counter as CounterType
from typing import Dict, List, Optional, Set, Tuple

from bacpypes3.analysis import decode_file, decode_packet, settings
from bacpypes3.basetypes import Address, ObjectIdentifier
from bacpypes3.npdu import NPDU
from bacpypes3.pdu import PDU

settings.route_aware = True


@dataclass
class DeviceInfo:
    device_id: int
    address: Address  # IP address
    bacnet_address: Optional[str] = None  # <network>:<mac> format
    observed_at: float = 0
    vendor_id: Optional[int] = None
    max_apdu_length: Optional[int] = None
    segmentation: Optional[str] = None
    forwarded: bool = False  # Whether this device was seen through a BBMD/router


@dataclass
class AddressStats:
    total_packets: int = 0
    message_types: CounterType = field(default_factory=Counter)
    routed_messages: int = 0
    non_routed_messages: int = 0
    unicast_messages: int = 0
    broadcast_messages: int = 0
    forwarded_packets: int = 0


class BACnetPcapAnalyzer:
    def __init__(self, debug=False):
        self.address_stats: Dict[str, AddressStats] = defaultdict(AddressStats)
        self.device_cache: Dict[str, DeviceInfo] = {}
        self.debug = debug

    def process_pcap(self, filepath):
        """Process a PCAP file and analyze BACnet packets."""
        for frame in decode_file(filepath):
            self._process_packet(frame)

    def _process_packet(self, frame):
        """Process an individual BACnet packet."""
        # Extract packet time from frame
        pkt_time = frame._timestamp if hasattr(frame, "_timestamp") else 0

        # Debug: Print frame information
        if self.debug:
            self._debug_frame(frame)

        # Get IP information
        ip_src = None
        ip_dst = None
        if hasattr(frame, "ipv4") and frame.ipv4:
            ip_src = str(frame.ipv4.source_address)
            ip_dst = str(frame.ipv4.destination_address)

        # Handle BACnet/IP packets
        if hasattr(frame, "udp") and frame.udp and frame.udp.source_port == 47808:
            # BACnet/IP uses UDP port 47808 (0xBAC0)
            if ip_src:
                self._update_stats(
                    ip_src,
                    "BACnet/IP",
                    ip_dst,
                    is_broadcast=ip_dst.endswith("255.255.255"),
                )

            # Check if this is a forwarded NPDU (from a BACnet router/BBMD)
            if hasattr(frame, "bvll") and frame.bvll:
                bvll_type = type(frame.bvll).__name__

                if ip_src:
                    self._update_stats(ip_src, bvll_type, ip_dst)

                # For forwarded NPDU, track the original address if available
                if bvll_type == "ForwardedNPDU":
                    if frame.npci and hasattr(frame.npci, "npduSADR"):
                        # Extract source address from NPDU
                        npdu_sadr = frame.npci.npduSADR
                        if hasattr(npdu_sadr, "addrAddr"):
                            mac_bytes = npdu_sadr.addrAddr
                            mac = (
                                "".join(f"{b:02x}" for b in mac_bytes)
                                if mac_bytes
                                else None
                            )
                            if mac:
                                # Create a unique source identifier for stats
                                actual_source = f"{npdu_sadr.addrNet}:{mac}"
                                self._update_stats(
                                    actual_source, "ForwardedNPDU", ip_dst
                                )
                    if ip_src:
                        self.address_stats[ip_src].forwarded_packets += 1

                    # Process forwarded NPDU with original source address
                    if hasattr(frame.bvll, "bvlciAddress") and frame.bvll.bvlciAddress:
                        router_addr = str(frame.bvll.bvlciAddress)
                        if self.debug:
                            print(
                                f"Processing forwarded NPDU from router {router_addr}"
                            )
                        self._process_forwarded_npdu(frame.bvll, ip_dst, pkt_time)

                    # Check if this ForwardedNPDU has an I-Am message
                    if hasattr(frame.bvll, "npdu") and frame.bvll.npdu:
                        npdu = frame.bvll.npdu
                        if hasattr(npdu, "apdu") and npdu.apdu:
                            apdu = npdu.apdu
                            apdu_type = type(apdu).__name__
                            # Add the APDU type to the statistics
                            self._update_stats(original_src, apdu_type, destination)
                            
                            # Check for service choice and add separate entry
                            if hasattr(apdu, 'apduService'):
                                service_choice = apdu.apduService
                                
                                # Map service choice to a standard message type name
                                service_type_mapping = {
                                    0: "IAmRequest",
                                    1: "IHaveRequest",  # IHave service
                                    7: "WhoHasRequest", # WhoHas service
                                    8: "WhoIsRequest"
                                }
                                
                                # If we have a recognized service choice, add it as a separate entry
                                if service_choice in service_type_mapping:
                                    service_type = service_type_mapping[service_choice]
                                    
                                    # Only add if it's different from the original class name
                                    # to avoid double counting
                                    if service_type != apdu_type:
                                        if self.debug:
                                            print(f"Adding service type {service_type} (choice {service_choice}) for {apdu_type} in NPDU")
                                        self._update_stats(original_src, service_type, destination)

                            if apdu_type == "IAmRequest":
                                # Process with our new method to extract network/MAC address
                                self._process_i_am_request_new(frame, is_forwarded=True)

            # Process direct APDU (application layer BACnet messages)
            if hasattr(frame, "apdu") and frame.apdu:
                # Pass the NPDU if available for source address extraction
                npdu = frame.npdu if hasattr(frame, "npdu") else None
                if self.debug:
                    print(f"Processing direct APDU from {ip_src}")

                # Check if this is an I-Am message
                apdu_type = type(frame.apdu).__name__
                # Add the APDU type to the statistics
                self._update_stats(ip_src, apdu_type, ip_dst)

                if apdu_type == "IAmRequest":
                    # Process with our new method to extract network/MAC address
                    self._process_i_am_request_new(frame, is_forwarded=False)
                else:
                    # Process other APDU types with the existing method
                    self._process_apdu(frame.apdu, ip_src, ip_dst, pkt_time, npdu)

    def _process_forwarded_npdu(self, bvll, destination, pkt_time):
        """Process a forwarded NPDU message (from a BACnet router/BBMD)."""
        # Get the forwarding router address
        original_src = str(bvll.bvlciAddress) if hasattr(bvll, "bvlciAddress") else None
        if not original_src:
            if self.debug:
                print("Error: Forwarded NPDU without bvlciAddress")
            return

        # Initialize default values
        network = None
        mac = None
        source_stats_updated = False

        if self.debug:
            print(f"Analyzing forwarded NPDU from router {original_src}")

        # First try to extract information from the decoded NPDU if available
        if hasattr(bvll, "npdu") and bvll.npdu:
            npdu = bvll.npdu

            # Extract BACnet network information from the source NPDU address
            if hasattr(npdu, "npduSADR") and npdu.npduSADR:
                sadr = npdu.npduSADR

                # Get address type if available
                addr_type = getattr(sadr, "addrType", None)

                # Extract network number
                if hasattr(sadr, "addrNet"):
                    network = sadr.addrNet
                    if self.debug:
                        print(
                            f"Found BACnet source network: {network}, type: {addr_type}"
                        )

                # Extract MAC address
                if hasattr(sadr, "addrAddr"):
                    mac_bytes = sadr.addrAddr
                    mac = "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else None
                    if self.debug:
                        print(
                            f"Found BACnet source MAC: {mac}, raw bytes: {sadr.addrAddr!r}"
                        )
                        if network is not None:
                            print(f"Complete BACnet address: {network}:{mac}")

            # Check if NPDU contains an APDU
            if hasattr(npdu, "apdu") and npdu.apdu:
                apdu = npdu.apdu
               
               
                # Create a unique source identifier for stats if we have network and MAC
                actual_source = None
                if network is not None and mac is not None:
                    actual_source = f"{network}:{mac}"
                    # Update statistics for the actual device, not just the router
                    self._update_stats(actual_source, apdu_type, destination)
                    source_stats_updated = True
                    self._update_stats(actual_source, type(apdu).__name__, destination)
                    
                    # Check for service choice and add separate entry
                    if hasattr(apdu, 'apduService'):
                        service_choice = apdu.apduService
                        
                        # Map service choice to a standard message type name
                        service_type_mapping = {
                            0: "IAmRequest",
                            1: "IHaveRequest",  # IHave service
                            7: "WhoHasRequest", # WhoHas service
                            8: "WhoIsRequest"
                        }
                        
                        # If we have a recognized service choice, add it as a separate entry
                        if service_choice in service_type_mapping:
                            service_type = service_type_mapping[service_choice]
                            
                            # Only add if it's different from the original class name
                            # to avoid double counting
                            if service_type != apdu_type:
                                if self.debug:
                                    print(f"Adding service type {service_type} (choice {service_choice}) for {apdu_type}")
                                    # For WhoHas or IHave, print detailed info for debugging
                                    if service_choice in [1, 7]:
                                        svc_name = "WhoHas" if service_choice == 7 else "IHave"
                                        print(f"Found {svc_name} message (service {service_choice}) from {actual_source}")
                                        
                                self._update_stats(actual_source, service_type, destination)

                # Also update router stats
                if not source_stats_updated:
                    self._update_stats(original_src, apdu_type, destination)
                    
                    # Check for service choice and add separate entry
                    if hasattr(apdu, 'apduService'):
                        service_choice = apdu.apduService
                        print(service_choice)
                        
                        # If we have a recognized service choice, add it as a separate entry
                        if service_choice in service_type_mapping:
                            service_type = service_type_mapping[service_choice]
                            
                            # Only add if it's different from the original class name
                            # to avoid double counting
                            if service_type != apdu_type:
                                if self.debug:
                                    print(f"Adding service type {service_type} (choice {service_choice}) for {apdu_type}")
                                    # For WhoHas or IHave, print detailed info for debugging
                                    if service_choice in [1, 7]:
                                        svc_name = "WhoHas" if service_choice == 7 else "IHave"
                                        print(f"Found {svc_name} message (service {service_choice}) from {original_src}")
                                
                                self._update_stats(original_src, service_type, destination)

                # Process I-Am messages - this path is kept for backward compatibility
                # Note: The main _process_packet method now handles IAmRequest directly
                # This code will only run if an IAmRequest is processed outside the main method
                if apdu_type == "IAmRequest" and hasattr(apdu, "iAmDeviceIdentifier"):
                    # Process I-Am message with the NPDU for address extraction
                    # Explicitly set forwarded=True since this is a forwarded NPDU
                    self._process_i_am_request(
                        apdu, original_src, pkt_time, npdu, is_forwarded=True
                    )

                    if self.debug:
                        print(
                            f"Found I-Am in forwarded packet NPDU (legacy path), via router {original_src}"
                        )

        # Fallback: If no valid NPDU found or network address not extracted, try to decode the raw pduData
        if hasattr(bvll, "pduData") and bvll.pduData:
            try:
                # Attempt to decode the packet directly from raw data
                decoded_pkt = decode_packet(bvll.pduData)

                if decoded_pkt:
                    # Try to extract network info if not already found
                    if (
                        network is None
                        and hasattr(decoded_pkt, "npdu")
                        and decoded_pkt.npdu
                    ):
                        npdu = decoded_pkt.npdu
                        if hasattr(npdu, "npduSADR") and npdu.npduSADR:
                            network = getattr(npdu.npduSADR, "addrNet", None)
                            if hasattr(npdu.npduSADR, "addrAddr"):
                                mac_bytes = npdu.npduSADR.addrAddr
                                mac = (
                                    "".join(f"{b:02x}" for b in mac_bytes)
                                    if mac_bytes
                                    else None
                                )

                    # Try to process the decoded APDU
                    if hasattr(decoded_pkt, "apdu"):
                        apdu = decoded_pkt.apdu
                        apdu_type = type(apdu).__name__

                        # Update statistics for the actual device if we now have the info
                        if (
                            not source_stats_updated
                            and network is not None
                            and mac is not None
                        ):
                            actual_source = f"{network}:{mac}"
                            self._update_stats(actual_source, apdu_type, destination)
                            source_stats_updated = True

                        # Process I-Am message with the decoded NPDU for address extraction
                        if hasattr(apdu, "iAmDeviceIdentifier"):
                            self._process_i_am_request(
                                apdu,
                                original_src,
                                pkt_time,
                                (
                                    decoded_pkt.npdu
                                    if hasattr(decoded_pkt, "npdu")
                                    else None
                                ),
                                is_forwarded=True,
                            )

                            if self.debug:
                                print(
                                    f"Found I-Am in decoded packet, via router {original_src}"
                                )
            except Exception as e:
                if self.debug:
                    print(f"Error decoding forwarded NPDU data: {e}")

        # The device info is now processed through _process_i_am_request
        # We only need to handle non-IAm messages here if needed
        pass

    def _process_apdu(self, apdu, source, destination, pkt_time, npdu=None):
        """Process a BACnet Application Protocol Data Unit (APDU)."""
        apdu_type = type(apdu).__name__
        print(apdu_type)

        # Update statistics based on class name
        self._update_stats(source, apdu_type, destination)
        
        # Check for service choice and add additional entry based on service choice
        # This ensures we capture both the class name and the service type
        if hasattr(apdu, 'apduService'):
            service_choice = apdu.apduService
            
            # Map service choice to a standard message type name
            service_type_mapping = {
                0: "IAmRequest",
                1: "IHaveRequest",  # IHave service
                7: "WhoHasRequest", # WhoHas service
                8: "WhoIsRequest"
            }
            
            # If we have a recognized service choice, add it as a separate entry
            if service_choice in service_type_mapping:
                service_type = service_type_mapping[service_choice]
                
                # Only add if it's different from the original class name
                # to avoid double counting
                if service_type != apdu_type:
                    if self.debug:
                        print(f"Adding service type {service_type} (choice {service_choice}) for {apdu_type}")
                    self._update_stats(source, service_type, destination)
                    
                    # For WhoHas, print detailed info for debugging
                    if service_choice == 7 and self.debug:
                        print(f"Found WhoHas message (service 7) in {apdu_type} from {source}")
                        for attr in dir(apdu):
                            if not attr.startswith('_') and not callable(getattr(apdu, attr)):
                                try:
                                    value = getattr(apdu, attr)
                                    print(f"  {attr} = {value}")
                                except:
                                    pass

        if self.debug:
            print(f"Processing {apdu_type} from {source} to {destination}")

        # Handle I-Am requests (device advertisements) - this path is kept for backward compatibility
        # Note that the _process_packet method now routes I-Am messages to _process_i_am_request_new directly
        # This code will only run if the caller doesn't use _process_i_am_request_new
        if apdu_type == "IAmRequest" and hasattr(apdu, "iAmDeviceIdentifier"):
            device_id = getattr(apdu, "iAmDeviceIdentifier", None)
            if self.debug:
                print(
                    f"Found I-Am message from {source}, device ID: {device_id} (processed via legacy path)"
                )

            # Pass the NPDU if available for source address extraction
            # is_forwarded=False because this is a direct APDU, not through a router
            self._process_i_am_request(apdu, source, pkt_time, npdu, is_forwarded=False)

    def _process_i_am_request_new(self, frame, is_forwarded=False):
        """Process an I-Am request to extract device information from a complete frame."""
        # Get basic frame information
        pkt_time = frame._timestamp if hasattr(frame, "_timestamp") else 0

        # Get IP source address (router address for forwarded packets)
        source_addr = None
        if hasattr(frame, "ipv4") and frame.ipv4:
            source_addr = str(frame.ipv4.source_address)

        # For forwarded packets, try to get the original device address
        if is_forwarded and hasattr(frame, "bvll") and frame.bvll:
            if hasattr(frame.bvll, "bvlciAddress"):
                source_addr = str(frame.bvll.bvlciAddress)

        # If no source address available, we can't proceed
        if not source_addr:
            if self.debug:
                print("Error: No source address found in frame")
            return

        # Get the APDU
        apdu = None
        if hasattr(frame, "apdu") and frame.apdu:
            apdu = frame.apdu
        elif (
            hasattr(frame, "bvll")
            and frame.bvll
            and hasattr(frame.bvll, "npdu")
            and frame.bvll.npdu
        ):
            if hasattr(frame.bvll.npdu, "apdu"):
                apdu = frame.bvll.npdu.apdu

        if not apdu or not hasattr(apdu, "iAmDeviceIdentifier"):
            if self.debug:
                print("No valid I-Am APDU found in frame")
            return

        # Extract device ID
        device_id = None
        try:
            # Handle different formats of device ID
            device_id_info = apdu.iAmDeviceIdentifier

            if self.debug:
                print(
                    f"Processing device ID info: {device_id_info} (type: {type(device_id_info).__name__})"
                )

            if isinstance(device_id_info, tuple) and len(device_id_info) == 2:
                # Format: ("device", 123)
                device_id = device_id_info[1]
                if self.debug:
                    print(f"Extracted device ID {device_id} from tuple format")
            elif hasattr(device_id_info, "instance"):
                # Format: ObjectIdentifier with instance attribute
                device_id = device_id_info.instance
                if self.debug:
                    print(f"Extracted device ID {device_id} from ObjectIdentifier")
            elif isinstance(device_id_info, str) and "," in device_id_info:
                # Format: "device,123"
                device_id = int(device_id_info.split(",")[1])
                if self.debug:
                    print(f"Extracted device ID {device_id} from string format")
            else:
                # Try parsing as string
                device_id_str = str(device_id_info)
                if "," in device_id_str:
                    device_id = int(device_id_str.split(",")[1])
                    if self.debug:
                        print(
                            f"Extracted device ID {device_id} from string representation"
                        )
        except Exception as e:
            if self.debug:
                print(f"Error extracting device ID: {e}")
                print(f"Device ID type: {type(apdu.iAmDeviceIdentifier).__name__}")
                print(f"Device ID info: {repr(apdu.iAmDeviceIdentifier)}")
            return

        if device_id is None:
            if self.debug:
                print("Failed to extract a valid device ID")
            return

        # Extract additional device info if available
        vendor_id = getattr(apdu, "vendorID", None)
        max_apdu_length = getattr(apdu, "maxAPDULengthAccepted", None)
        segmentation = getattr(apdu, "segmentationSupported", None)

        # Try to extract network and MAC address from NPDU if provided
        network = None
        mac = None

        # Find NPDU in the frame
        npdu = None
        if frame.npci and hasattr(frame.npci, "npduSADR"):
            sadr = frame.npci.npduSADR
            npdu = frame.npdu
            # elif hasattr(frame, 'bvll') and frame.bvll and hasattr(frame.bvll, 'npdu'):
            #     npdu = frame.bvll.npdu

            # if npdu and hasattr(npdu, 'npduSADR') and npdu.npduSADR:
            #     sadr = npdu.npduSADR

            #     # Extract address details from the remoteStation
            addr_type = getattr(sadr, "addrType", None)

            # Extract network number if available
            if hasattr(sadr, "addrNet"):
                network = sadr.addrNet
                if self.debug:
                    print(
                        f"I-Am processing: Found source NPDU network: {network}, type: {addr_type}"
                    )

            # Extract MAC address if available
            if hasattr(sadr, "addrAddr"):
                mac_bytes = sadr.addrAddr
                mac = "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else None
                if self.debug:
                    print(
                        f"I-Am processing: Found source NPDU MAC: {mac}, raw bytes: {sadr.addrAddr!r}"
                    )
                    print(f"I-Am processing: BACnet address is {network}:{mac}")
                    print(
                        f"I-Am processing: Full NPDU source address info: {sadr.__dict__ if hasattr(sadr, '__dict__') else 'No __dict__'}"
                    )

        # Create a device key based on available network information
        if network is not None and mac is not None:
            # If we have full BACnet network address information, use that
            device_key = f"{network}:{mac}"
            key_type = "BACnet network address"
            if self.debug:
                print(
                    f"DEBUG: Using BACnet network address {device_key} for device {device_id}"
                )
        else:
            # Otherwise use local network (0) with source IP address
            device_key = f"0:{source_addr}"
            key_type = "IP address"
            if self.debug:
                print(f"DEBUG: Using IP address {device_key} for device {device_id}")

        if self.debug:
            print(f"Using {key_type} {device_key} for device {device_id}")
            if is_forwarded:
                print(f"Device {device_id} was seen through a forwarded NPDU")

            # Log information about what type of addressing was found/used
            if network is None:
                print(f"No network number found for device {device_id}")
            if mac is None:
                print(f"No MAC address found for device {device_id}")
            elif network is not None:
                print(
                    f"Complete BACnet address {network}:{mac} found for device {device_id}"
                )

        # Add to device cache using the device key
        self.device_cache[device_key] = DeviceInfo(
            device_id=device_id,
            address=Address(source_addr),
            bacnet_address=device_key,
            observed_at=pkt_time,
            vendor_id=vendor_id,
            max_apdu_length=max_apdu_length,
            segmentation=segmentation,
            forwarded=is_forwarded,
        )

        # Also store by device ID for direct lookup
        # This allows lookup by device ID regardless of how it was discovered
        second_id_key = f"device:{device_id}"
        if second_id_key not in self.device_cache:
            # Only store the first instance of a device ID we see
            self.device_cache[second_id_key] = DeviceInfo(
                device_id=device_id,
                address=Address(source_addr),
                bacnet_address=device_key,  # Store the actual BACnet address here
                observed_at=pkt_time,
                vendor_id=vendor_id,
                max_apdu_length=max_apdu_length,
                segmentation=segmentation,
                forwarded=is_forwarded,
            )

    def _process_i_am_request(
        self, apdu, source_addr, pkt_time, npdu=None, is_forwarded=False
    ):
        """Process an I-Am request to extract device information."""
        if not hasattr(apdu, "iAmDeviceIdentifier"):
            return

        # Extract device ID
        device_id = None
        try:
            # Handle different formats of device ID
            device_id_info = apdu.iAmDeviceIdentifier

            if self.debug:
                print(
                    f"Processing device ID info: {device_id_info} (type: {type(device_id_info).__name__})"
                )

            if isinstance(device_id_info, tuple) and len(device_id_info) == 2:
                # Format: ("device", 123)
                device_id = device_id_info[1]
                if self.debug:
                    print(f"Extracted device ID {device_id} from tuple format")
            elif hasattr(device_id_info, "instance"):
                # Format: ObjectIdentifier with instance attribute
                device_id = device_id_info.instance
                if self.debug:
                    print(f"Extracted device ID {device_id} from ObjectIdentifier")
            elif isinstance(device_id_info, str) and "," in device_id_info:
                # Format: "device,123"
                device_id = int(device_id_info.split(",")[1])
                if self.debug:
                    print(f"Extracted device ID {device_id} from string format")
            else:
                # Try parsing as string
                device_id_str = str(device_id_info)
                if "," in device_id_str:
                    device_id = int(device_id_str.split(",")[1])
                    if self.debug:
                        print(
                            f"Extracted device ID {device_id} from string representation"
                        )
        except Exception as e:
            if self.debug:
                print(f"Error extracting device ID: {e}")
                print(f"Device ID type: {type(apdu.iAmDeviceIdentifier).__name__}")
                print(f"Device ID info: {repr(apdu.iAmDeviceIdentifier)}")
            return

        if device_id is None:
            if self.debug:
                print("Failed to extract a valid device ID")
            return

        # Extract additional device info if available
        vendor_id = getattr(apdu, "vendorID", None)
        max_apdu_length = getattr(apdu, "maxAPDULengthAccepted", None)
        segmentation = getattr(apdu, "segmentationSupported", None)

        # Try to extract network and MAC address from NPDU if provided
        network = None
        mac = None

        if npdu and hasattr(npdu, "npduSADR") and npdu.npduSADR:
            sadr = npdu.npduSADR

            # Extract address details from the remoteStation
            addr_type = getattr(sadr, "addrType", None)

            # Extract network number if available
            if hasattr(sadr, "addrNet"):
                network = sadr.addrNet
                if self.debug:
                    print(
                        f"I-Am processing: Found source NPDU network: {network}, type: {addr_type}"
                    )

            # Extract MAC address if available
            if hasattr(sadr, "addrAddr"):
                mac_bytes = sadr.addrAddr
                mac = "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else None
                if self.debug:
                    print(
                        f"I-Am processing: Found source NPDU MAC: {mac}, raw bytes: {sadr.addrAddr!r}"
                    )
                    print(f"I-Am processing: BACnet address is {network}:{mac}")
                    print(
                        f"I-Am processing: Full NPDU source address info: {sadr.__dict__ if hasattr(sadr, '__dict__') else 'No __dict__'}"
                    )

        # Create a device key based on available network information
        if network is not None and mac is not None:
            # If we have full BACnet network address information, use that
            device_key = f"{network}:{mac}"
            key_type = "BACnet network address"
            (
                print(
                    f"DEBUG: Using BACnet network address {device_key} for device {device_id}"
                )
                if self.debug
                else None
            )
        else:
            # Otherwise use local network (0) with source IP address
            device_key = f"0:{source_addr}"
            key_type = "IP address"
            (
                print(f"DEBUG: Using IP address {device_key} for device {device_id}")
                if self.debug
                else None
            )

        if self.debug:
            print(f"Using {key_type} {device_key} for device {device_id}")
            if is_forwarded:
                print(f"Device {device_id} was seen through a forwarded NPDU")

            # Log information about what type of addressing was found/used
            if network is None:
                print(f"No network number found for device {device_id}")
            if mac is None:
                print(f"No MAC address found for device {device_id}")
            elif network is not None:
                print(
                    f"Complete BACnet address {network}:{mac} found for device {device_id}"
                )

        # Create a key for device ID lookup
        device_id_key = str(device_id)

        # Add to device cache
        self.device_cache[device_key] = DeviceInfo(
            device_id=device_id,
            address=Address(source_addr),
            bacnet_address=device_key,
            observed_at=pkt_time,
            vendor_id=vendor_id,
            max_apdu_length=max_apdu_length,
            segmentation=segmentation,
            forwarded=is_forwarded,
        )

        # Also store by device ID for direct lookup
        # This allows lookup by device ID regardless of how it was discovered
        # Use second_id_key to avoid overwriting the original key
        second_id_key = f"device:{device_id}"
        if second_id_key not in self.device_cache:
            # Only store the first instance of a device ID we see
            self.device_cache[second_id_key] = DeviceInfo(
                device_id=device_id,
                address=Address(source_addr),
                bacnet_address=device_key,  # Store the actual BACnet address here
                observed_at=pkt_time,
                vendor_id=vendor_id,
                max_apdu_length=max_apdu_length,
                segmentation=segmentation,
                forwarded=is_forwarded,
            )

    def _update_stats(
        self,
        src_addr: str,
        msg_type: str,
        dest_addr: Optional[str] = None,
        is_routed: bool = None,
        is_broadcast: bool = None,
        pkt_time: float = 0,
    ):
        """Update the statistics for a given source address and message."""
        if not src_addr or not msg_type:
            return

        # Update packet count and message type
        self.address_stats[src_addr].total_packets += 1
        self.address_stats[src_addr].message_types[msg_type] += 1

        # Check if routed (based on message type or explicit flag)
        if is_routed is None:
            is_routed = msg_type in (
                "ForwardedNPDU",
                "RouterToNetwork",
                "NetworkToRouter",
            )

        if is_routed:
            self.address_stats[src_addr].routed_messages += 1
        else:
            self.address_stats[src_addr].non_routed_messages += 1

        # Check if broadcast (based on destination address or explicit flag)
        if is_broadcast is None and dest_addr:
            is_broadcast = (
                "255.255.255.255" in dest_addr
                or "*.255.255.255" in dest_addr
                or "*" in dest_addr
            )

        if is_broadcast:
            self.address_stats[src_addr].broadcast_messages += 1
        else:
            self.address_stats[src_addr].unicast_messages += 1

    def _debug_frame(self, frame):
        """Print debug information about a frame."""
        print("\n----- Frame Debug -----")
        print(f"Frame attributes: {dir(frame)}")

        if hasattr(frame, "ipv4") and frame.ipv4:
            print(
                f"IPv4: src={frame.ipv4.source_address}, dst={frame.ipv4.destination_address}"
            )

        if hasattr(frame, "udp") and frame.udp:
            print(
                f"UDP: src_port={frame.udp.source_port}, dst_port={frame.udp.destination_port}"
            )

        if hasattr(frame, "bvlci") and frame.bvlci:
            print(
                f"BVLCI: type={frame.bvlci.bvlciType}, function={frame.bvlci.bvlciFunction}"
            )

        # Print NPDU info if available
        if hasattr(frame, "npdu") and frame.npdu:
            print(f"NPDU: {type(frame.npdu).__name__}")
            for attr in dir(frame.npdu):
                if not attr.startswith("_") and attr not in (
                    "encode",
                    "decode",
                    "copy",
                    "dict_contents",
                ):
                    try:
                        value = getattr(frame.npdu, attr)
                        print(f"  NPDU.{attr}: {value}")
                    except:
                        pass

            # Specifically check for npduSADR (source address)
            if hasattr(frame.npdu, "npduSADR") and frame.npdu.npduSADR:
                print(f"  NPDU Source Address:")
                sadr = frame.npdu.npduSADR
                if hasattr(sadr, "addrType"):
                    print(f"    Type: {sadr.addrType}")
                if hasattr(sadr, "addrNet"):
                    print(f"    Network: {sadr.addrNet}")
                if hasattr(sadr, "addrAddr"):
                    mac_bytes = sadr.addrAddr
                    mac_hex = (
                        "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else "None"
                    )
                    print(f"    MAC: {mac_hex} (hex: {sadr.addrAddr!r})")
                    print(f"    BACnet Address: {sadr.addrNet}:{mac_hex}")

        if hasattr(frame, "bvll") and frame.bvll:
            print(f"BVLL type: {type(frame.bvll).__name__}")
            # Try to print more BVLL details
            for attr in dir(frame.bvll):
                if not attr.startswith("_") and attr not in (
                    "encode",
                    "decode",
                    "copy",
                    "dict_contents",
                ):
                    try:
                        value = getattr(frame.bvll, attr)
                        print(f"  BVLL.{attr}: {value}")
                    except:
                        pass

            # Print NPDU inside BVLL if it's a forwarded message
            if hasattr(frame.bvll, "npdu") and frame.bvll.npdu:
                print(f"  BVLL.NPDU: {type(frame.bvll.npdu).__name__}")
                for attr in dir(frame.bvll.npdu):
                    if not attr.startswith("_") and attr not in (
                        "encode",
                        "decode",
                        "copy",
                        "dict_contents",
                    ):
                        try:
                            value = getattr(frame.bvll.npdu, attr)
                            print(f"    BVLL.NPDU.{attr}: {value}")
                        except:
                            pass

                # Specifically check for npduSADR (source address) in BVLL.NPDU
                if hasattr(frame.bvll.npdu, "npduSADR") and frame.bvll.npdu.npduSADR:
                    print(f"    BVLL.NPDU Source Address:")
                    sadr = frame.bvll.npdu.npduSADR
                    if hasattr(sadr, "addrType"):
                        print(f"      Type: {sadr.addrType}")
                    if hasattr(sadr, "addrNet"):
                        print(f"      Network: {sadr.addrNet}")
                    if hasattr(sadr, "addrAddr"):
                        mac_bytes = sadr.addrAddr
                        mac_hex = (
                            "".join(f"{b:02x}" for b in mac_bytes)
                            if mac_bytes
                            else "None"
                        )
                        print(f"      MAC: {mac_hex} (hex: {sadr.addrAddr!r})")
                        print(f"      BACnet Address: {sadr.addrNet}:{mac_hex}")

                # Print APDU inside NPDU if present
                if hasattr(frame.bvll.npdu, "apdu") and frame.bvll.npdu.apdu:
                    print(f"    BVLL.NPDU.APDU: {type(frame.bvll.npdu.apdu).__name__}")
                    for attr in dir(frame.bvll.npdu.apdu):
                        if not attr.startswith("_") and attr not in (
                            "encode",
                            "decode",
                            "copy",
                            "dict_contents",
                        ):
                            try:
                                value = getattr(frame.bvll.npdu.apdu, attr)
                                print(f"      BVLL.NPDU.APDU.{attr}: {value}")
                            except:
                                pass

        if hasattr(frame, "apdu") and frame.apdu:
            print(f"APDU type: {type(frame.apdu).__name__}")
            for attr in dir(frame.apdu):
                if not attr.startswith("_") and attr not in (
                    "encode",
                    "decode",
                    "copy",
                    "dict_contents",
                ):
                    try:
                        value = getattr(frame.apdu, attr)
                        print(f"  APDU.{attr}: {value}")
                    except:
                        pass

        # If we have a ForwardedNPDU, show raw data in hex for debugging
        if hasattr(frame, "bvll") and frame.bvll and hasattr(frame.bvll, "pduData"):
            print("  Raw BVLL pduData (hex):")
            data = frame.bvll.pduData
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_values = " ".join(f"{b:02x}" for b in chunk)
                ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                print(f"    {i:04x}: {hex_values:<47} | {ascii_values}")

        print("------------------------")

    def print_summary(self):
        """Print a summary of the analysis results."""
        print("\n=== BACnet Traffic Analysis ===\n")

        print("Address Statistics:")
        for addr, stats in sorted(self.address_stats.items()):
            print(f"\n  {addr}:")
            print(f"    Total Packets: {stats.total_packets}")
            print(f"    Message Types: {dict(stats.message_types)}")
            print(
                f"    Routed: {stats.routed_messages}, Non-Routed: {stats.non_routed_messages}"
            )
            print(
                f"    Unicast: {stats.unicast_messages}, Broadcast: {stats.broadcast_messages}"
            )
            if stats.forwarded_packets > 0:
                print(f"    Forwarded Packets: {stats.forwarded_packets}")

        print("\n=== Discovered BACnet Devices ===")
        if not self.device_cache:
            print("  No devices found in I-Am messages")
        else:
            # Filter out the device:{id} entries and just use them for info
            id_based_devices = {
                k: v for k, v in self.device_cache.items() if k.startswith("device:")
            }
            address_based_devices = {
                k: v
                for k, v in self.device_cache.items()
                if not k.startswith("device:")
            }

            # Group devices by ID for better display
            devices_by_id = {}
            for bacnet_addr, info in address_based_devices.items():
                devices_by_id.setdefault(info.device_id, []).append((bacnet_addr, info))

            # Check if we have any real remote station addresses
            any_remote_station = False
            for bacnet_addr, info in address_based_devices.items():
                addr_parts = bacnet_addr.split(":")
                if addr_parts[0] != "0" or len(addr_parts) > 2:
                    any_remote_station = True
                    break

            # Print a note if we don't have any real remote station addresses
            if not any_remote_station and address_based_devices:
                print(
                    "\n  Note: No BACnet MS/TP or remote network devices were found in this capture."
                )
                print("  This suggests one of the following:")
                print("  1. The capture only includes BACnet/IP devices")
                print(
                    "  2. Forwarded packets don't contain complete NPDU source address information"
                )
                print("  3. All devices are on the local BACnet network")

            # Now print the devices, grouped by device ID
            for device_id, device_entries in sorted(devices_by_id.items()):
                print(f"\n  Device ID: {device_id}")

                # Count by address type to provide better summary
                ip_count = 0
                remote_station_count = 0

                for i, (bacnet_addr, info) in enumerate(sorted(device_entries)):
                    # Get the actual BACnet address from the device info
                    actual_bacnet_addr = info.bacnet_address

                    # Determine address type from format
                    addr_parts = actual_bacnet_addr.split(":")
                    is_ip_based = addr_parts[0] == "0" and len(addr_parts) == 2
                    is_remote_station = not is_ip_based

                    if is_ip_based:
                        ip_count += 1
                    else:
                        remote_station_count += 1

                    # Print appropriate address type with consistent formatting
                    if is_remote_station:
                        # Remote station device with network and MAC address
                        net_num = addr_parts[0]
                        mac_addr = ":".join(addr_parts[1:])
                        device_type = "MS/TP" if len(mac_addr) <= 4 else "Network"
                        print(f"    Address: BACnet {device_type} {net_num}:{mac_addr}")
                    else:
                        # Check if it came through a BBMD/router
                        is_forwarded = getattr(info, "forwarded", False)
                        if is_forwarded:
                            print(f"    Address: Forwarded via {addr_parts[1]}")
                        else:
                            # Direct BACnet/IP device
                            print(f"    Address: BACnet/IP {addr_parts[1]}")

                    # Show additional device information with consistent indentation
                    additional_info = []
                    if info.vendor_id is not None:
                        additional_info.append(f"Vendor ID: {info.vendor_id}")
                    if info.max_apdu_length is not None:
                        additional_info.append(f"Max APDU: {info.max_apdu_length}")
                    if info.segmentation is not None:
                        additional_info.append(f"Segmentation: {info.segmentation}")

                    if additional_info:
                        print(f"    Properties: {', '.join(additional_info)}")

                    # Add a separation line if there are multiple entries for this device
                    if i < len(device_entries) - 1:
                        print("    ---")

                # Add a summary of address types if there are multiple entries
                if (ip_count + remote_station_count) > 1:
                    types = []
                    if ip_count > 0:
                        types.append(f"{ip_count} BACnet/IP")
                    if remote_station_count > 0:
                        types.append(f"{remote_station_count} remote network")
                    print(f"    Summary: {', '.join(types)} instances of this device")


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <pcap_file> [--debug]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    debug_mode = len(sys.argv) > 2 and sys.argv[2] == "--debug"

    analyzer = BACnetPcapAnalyzer(debug=debug_mode)

    try:
        print(f"Analyzing {pcap_file}...")
        analyzer.process_pcap(pcap_file)
        analyzer.print_summary()
    except Exception as e:
        print(f"Error analyzing file: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
