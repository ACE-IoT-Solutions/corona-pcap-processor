"""
Reporting functions for BACnet PCAP Analyzer.
"""

from typing import Dict, List, Set

from .models import AddressStats, DeviceInfo, AnalysisResults


def generate_stats_report(address_stats: Dict[str, AddressStats]) -> List[str]:
    """Generate a report of address statistics.
    
    Args:
        address_stats: Dictionary of address statistics
        
    Returns:
        A list of report lines
    """
    report_lines = []
    report_lines.append("\n=== BACnet Traffic Analysis ===\n")
    
    report_lines.append("Address Statistics:")
    for addr, stats in sorted(address_stats.items()):
        report_lines.append(f"\n  {addr}:")
        report_lines.append(f"    Total Packets: {stats.total_packets}")
        report_lines.append(f"    Message Types: {dict(stats.message_types)}")
        report_lines.append(
            f"    Routed: {stats.routed_messages}, Non-Routed: {stats.non_routed_messages}"
        )
        report_lines.append(
            f"    Unicast: {stats.unicast_messages}, Broadcast: {stats.broadcast_messages}"
        )
        if stats.forwarded_packets > 0:
            report_lines.append(f"    Forwarded Packets: {stats.forwarded_packets}")
    
    return report_lines


def generate_devices_report(device_cache: Dict[str, DeviceInfo]) -> List[str]:
    """Generate a report of discovered BACnet devices.
    
    Args:
        device_cache: Dictionary of device information
        
    Returns:
        A list of report lines
    """
    report_lines = []
    report_lines.append("\n=== Discovered BACnet Devices ===")
    
    if not device_cache:
        report_lines.append("  No devices found in I-Am messages")
        return report_lines
    
    # Filter out the device:{id} entries and just use them for info
    id_based_devices = {
        k: v for k, v in device_cache.items() if k.startswith("device:")
    }
    address_based_devices = {
        k: v
        for k, v in device_cache.items()
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
        report_lines.append(
            "\n  Note: No BACnet MS/TP or remote network devices were found in this capture."
        )
        report_lines.append("  This suggests one of the following:")
        report_lines.append("  1. The capture only includes BACnet/IP devices")
        report_lines.append(
            "  2. Forwarded packets don't contain complete NPDU source address information"
        )
        report_lines.append("  3. All devices are on the local BACnet network")
    
    # Now print the devices, grouped by device ID
    for device_id, device_entries in sorted(devices_by_id.items()):
        report_lines.append(f"\n  Device ID: {device_id}")
        
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
                report_lines.append(f"    Address: BACnet {device_type} {net_num}:{mac_addr}")
            else:
                # Check if it came through a BBMD/router
                is_forwarded = info.forwarded
                if is_forwarded:
                    report_lines.append(f"    Address: Forwarded via {addr_parts[1]}")
                else:
                    # Direct BACnet/IP device
                    report_lines.append(f"    Address: BACnet/IP {addr_parts[1]}")
            
            # Show additional device information with consistent indentation
            additional_info = []
            if info.vendor_id is not None:
                additional_info.append(f"Vendor ID: {info.vendor_id}")
            if info.max_apdu_length is not None:
                additional_info.append(f"Max APDU: {info.max_apdu_length}")
            if info.segmentation is not None:
                additional_info.append(f"Segmentation: {info.segmentation}")
            
            if additional_info:
                report_lines.append(f"    Properties: {', '.join(additional_info)}")
            
            # Add a separation line if there are multiple entries for this device
            if i < len(device_entries) - 1:
                report_lines.append("    ---")
        
        # Add a summary of address types if there are multiple entries
        if (ip_count + remote_station_count) > 1:
            types = []
            if ip_count > 0:
                types.append(f"{ip_count} BACnet/IP")
            if remote_station_count > 0:
                types.append(f"{remote_station_count} remote network")
            report_lines.append(f"    Summary: {', '.join(types)} instances of this device")
    
    return report_lines


def generate_full_report(results: AnalysisResults) -> List[str]:
    """Generate a full report of analysis results.
    
    Args:
        results: The analysis results
        
    Returns:
        A list of report lines
    """
    report_lines = []
    
    # Add stats report
    report_lines.extend(generate_stats_report(results.address_stats))
    
    # Add devices report
    report_lines.extend(generate_devices_report(results.device_cache))
    
    return report_lines


def print_report(report_lines: List[str]) -> None:
    """Print a report to the console.
    
    Args:
        report_lines: List of report lines
    """
    for line in report_lines:
        print(line)