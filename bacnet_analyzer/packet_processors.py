"""
Functions for processing BACnet packets from PCAP files.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast

from bacpypes3.basetypes import Address, ObjectIdentifier
from bacpypes3.pdu import PDU

from .constants import ROUTED_MESSAGE_TYPES, SERVICE_CHOICE_TO_TYPE
from .models import DeviceInfo


def extract_source_dest_addresses(frame: Any) -> Tuple[Optional[str], Optional[str], bool]:
    """Extract source and destination IP addresses from a frame.

    Args:
        frame: The BACnet frame to process

    Returns:
        A tuple of (source_addr, dest_addr, is_broadcast)
    """
    ip_src = None
    ip_dst = None
    is_broadcast = False

    if hasattr(frame, "ipv4") and frame.ipv4:
        ip_src = str(frame.ipv4.source_address)
        ip_dst = str(frame.ipv4.destination_address)

        # Check if it's a broadcast
        if ip_dst and ("255.255.255.255" in ip_dst or "*.255.255.255" in ip_dst or "*" in ip_dst):
            is_broadcast = True

    return ip_src, ip_dst, is_broadcast


def is_bacnet_ip_packet(frame: Any) -> bool:
    """Check if a frame is a BACnet/IP packet (UDP port 47808).

    Args:
        frame: The frame to check

    Returns:
        True if the frame is a BACnet/IP packet, False otherwise
    """
    return hasattr(frame, "udp") and frame.udp and frame.udp.source_port == 47808


def extract_service_choice(apdu: Any) -> Optional[int]:
    """Extract the service choice from an APDU.

    Args:
        apdu: The APDU to extract the service choice from

    Returns:
        The service choice as an integer, or None if not found
    """
    if hasattr(apdu, "apduService"):
        return apdu.apduService
    return None


def extract_apdu_type(apdu: Any) -> str:
    """Extract the APDU type as a string.

    Args:
        apdu: The APDU to extract the type from

    Returns:
        The APDU type as a string
    """
    # For bacpypes3 3.x, use type(apdu).__name__
    # For bacpypes3 4.x+, try to use apduType from apci attribute first
    if hasattr(apdu, "apci") and hasattr(apdu.apci, "apduType"):
        apdu_type_code = apdu.apci.apduType
        # Map APDU type code to class name
        from bacpypes3.apdu import apdu_types

        if apdu_type_code in apdu_types:
            return apdu_types[apdu_type_code].__name__

    # Fall back to type name if apci approach doesn't work
    return type(apdu).__name__


def extract_frame_timestamp(frame: Any) -> float:
    """Extract the timestamp from a frame.

    Args:
        frame: The frame to extract the timestamp from

    Returns:
        The timestamp as a float
    """
    return frame._timestamp if hasattr(frame, "_timestamp") else 0


def extract_network_and_mac(npdu: Any) -> Tuple[Optional[int], Optional[str]]:
    """Extract the network number and MAC address from an NPDU.

    Args:
        npdu: The NPDU to extract information from

    Returns:
        A tuple of (network, mac) where network is an integer or None,
        and mac is a string or None
    """
    network = None
    mac = None

    if npdu and hasattr(npdu, "npduSADR") and npdu.npduSADR:
        sadr = npdu.npduSADR

        # Extract network number if available
        if hasattr(sadr, "addrNet"):
            network = sadr.addrNet

        # Extract MAC address if available
        if hasattr(sadr, "addrAddr"):
            mac_bytes = sadr.addrAddr
            mac = "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else None

    return network, mac


def extract_device_id(apdu: Any) -> Optional[int]:
    """Extract the device ID from an I-Am request APDU.

    Args:
        apdu: The APDU to extract the device ID from

    Returns:
        The device ID as an integer, or None if not found
    """
    if not hasattr(apdu, "iAmDeviceIdentifier"):
        return None

    try:
        # Handle different formats of device ID
        device_id_info = apdu.iAmDeviceIdentifier

        if isinstance(device_id_info, tuple) and len(device_id_info) == 2:
            # Format: ("device", 123)
            return device_id_info[1]
        elif hasattr(device_id_info, "instance"):
            # Format: ObjectIdentifier with instance attribute
            return device_id_info.instance
        elif isinstance(device_id_info, str) and "," in device_id_info:
            # Format: "device,123"
            return int(device_id_info.split(",")[1])
        else:
            # Try parsing as string
            device_id_str = str(device_id_info)
            if "," in device_id_str:
                return int(device_id_str.split(",")[1])
    except Exception:
        # Any error means we couldn't extract a valid device ID
        pass

    return None


def extract_device_info(
    apdu: Any, source_addr: str, pkt_time: float, bacnet_address: str, is_forwarded: bool = False
) -> Optional[DeviceInfo]:
    """Extract device information from an I-Am request APDU.

    Args:
        apdu: The APDU to extract information from
        source_addr: The source address of the packet
        pkt_time: The timestamp of the packet
        bacnet_address: The BACnet address in format <network>:<mac>
        is_forwarded: Whether this APDU came through a forwarded NPDU

    Returns:
        A DeviceInfo object, or None if extraction failed
    """
    # Extract device ID
    device_id = extract_device_id(apdu)
    if device_id is None:
        return None

    # Extract additional device info if available
    vendor_id = getattr(apdu, "vendorID", None)
    max_apdu_length = getattr(apdu, "maxAPDULengthAccepted", None)
    segmentation = getattr(apdu, "segmentationSupported", None)

    # Create the device info object
    return DeviceInfo(
        device_id=device_id,
        address=Address(source_addr),
        bacnet_address=bacnet_address,
        observed_at=pkt_time,
        vendor_id=vendor_id,
        max_apdu_length=max_apdu_length,
        segmentation=segmentation,
        forwarded=is_forwarded,
    )
