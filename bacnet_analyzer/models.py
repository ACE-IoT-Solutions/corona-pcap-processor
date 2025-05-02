"""
Data models for BACnet PCAP Analyzer.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from typing import Counter as CounterType
from typing import Dict, FrozenSet, Mapping, Optional, Set

from bacpypes3.basetypes import Address


@dataclass(frozen=True)
class DeviceInfo:
    """Information about a discovered BACnet device."""

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
    """Statistics for a source address."""

    total_packets: int = 0
    message_types: CounterType = field(default_factory=Counter)
    routed_messages: int = 0
    non_routed_messages: int = 0
    unicast_messages: int = 0
    broadcast_messages: int = 0
    forwarded_packets: int = 0

    def update_message_type(self, msg_type: str, count: int = 1) -> None:
        """Update the counter for a message type.

        Args:
            msg_type: The message type to update
            count: The amount to increment the counter by (default: 1)
        """
        self.message_types[msg_type] += count

    def to_dict(self) -> Dict[str, Any]:
        """Convert the stats to a dictionary for serialization.

        Returns:
            A dictionary representation of the address stats
        """
        return {
            "total_packets": self.total_packets,
            "message_types": dict(self.message_types),
            "routed_messages": self.routed_messages,
            "non_routed_messages": self.non_routed_messages,
            "unicast_messages": self.unicast_messages,
            "broadcast_messages": self.broadcast_messages,
            "forwarded_packets": self.forwarded_packets,
        }


@dataclass
class AnalysisResults:
    """Results of analyzing a BACnet PCAP file."""

    address_stats: Dict[str, AddressStats] = field(default_factory=dict)
    device_cache: Dict[str, DeviceInfo] = field(default_factory=dict)
