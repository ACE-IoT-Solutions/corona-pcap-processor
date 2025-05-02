"""
Functions for managing device information extracted from BACnet packets.
"""

from typing import Dict, Optional, Tuple

from bacpypes3.basetypes import Address

from .models import DeviceInfo
from .packet_processors import extract_device_info, extract_network_and_mac


def get_device_key(network: Optional[int], mac: Optional[str], source_addr: str) -> Tuple[str, str]:
    """Generate a device key and determine the key type.

    Args:
        network: BACnet network number, or None if not available
        mac: BACnet MAC address as a hex string, or None if not available
        source_addr: IP address of the packet source

    Returns:
        A tuple of (device_key, key_type) where key_type is a descriptive string
    """
    if network is not None and mac is not None:
        # If we have full BACnet network address information, use that
        device_key = f"{network}:{mac}"
        key_type = "BACnet network address"
    else:
        # Otherwise use local network (0) with source IP address
        device_key = f"0:{source_addr}"
        key_type = "IP address"

    return device_key, key_type


def add_device_to_catalog(
    catalog: Dict[str, DeviceInfo], device_info: DeviceInfo
) -> Dict[str, DeviceInfo]:
    """Add a device to the device catalog.

    Args:
        catalog: The existing device catalog
        device_info: The device info to add

    Returns:
        The updated device catalog
    """
    # Make a shallow copy of the catalog
    updated_catalog = catalog.copy()

    # Add device using its BACnet address as the key
    if device_info.bacnet_address:
        updated_catalog[device_info.bacnet_address] = device_info

    # Also add using a device ID key for direct lookup
    # This allows lookup by device ID regardless of how it was discovered
    device_id_key = f"device:{device_info.device_id}"

    # Only add the device ID key if it doesn't already exist
    # (we want to keep the first instance we see)
    if device_id_key not in updated_catalog:
        updated_catalog[device_id_key] = device_info

    return updated_catalog
