"""
Functions for collecting and aggregating BACnet packet statistics.
"""

from typing import Dict, Optional, Set, Tuple

from .constants import ROUTED_MESSAGE_TYPES
from .models import AddressStats


def create_empty_stats() -> AddressStats:
    """Create a new, empty AddressStats object.

    Returns:
        An empty AddressStats object
    """
    return AddressStats()


def update_address_stats(
    stats: AddressStats,
    msg_type: str,
    is_broadcast: bool = False,
    is_routed: Optional[bool] = None,
    is_forwarded: bool = False,
) -> AddressStats:
    """Update the statistics for a given source address and message type.

    Args:
        stats: The existing AddressStats object to update
        msg_type: The message type to add
        is_broadcast: Whether this is a broadcast message
        is_routed: Whether this is a routed message (if None, determined from msg_type)
        is_forwarded: Whether this is a forwarded packet

    Returns:
        The updated AddressStats object
    """
    # Create a copy of the stats to avoid mutating the original
    updated_stats = AddressStats(
        total_packets=stats.total_packets + 1,
        message_types=stats.message_types.copy(),
        routed_messages=stats.routed_messages,
        non_routed_messages=stats.non_routed_messages,
        unicast_messages=stats.unicast_messages,
        broadcast_messages=stats.broadcast_messages,
        forwarded_packets=stats.forwarded_packets + (1 if is_forwarded else 0),
    )

    # Update message type count
    updated_stats.update_message_type(msg_type)

    # Determine if the message is routed based on type if not explicitly specified
    if is_routed is None:
        is_routed = msg_type in ROUTED_MESSAGE_TYPES

    # Update routing stats
    if is_routed:
        updated_stats.routed_messages += 1
    else:
        updated_stats.non_routed_messages += 1

    # Update broadcast/unicast stats
    if is_broadcast:
        updated_stats.broadcast_messages += 1
    else:
        updated_stats.unicast_messages += 1

    return updated_stats


def update_stats_dict(
    address_stats: Dict[str, AddressStats],
    src_addr: str,
    msg_type: str,
    is_broadcast: bool = False,
    is_routed: Optional[bool] = None,
    is_forwarded: bool = False,
) -> Dict[str, AddressStats]:
    """Update a dictionary of address statistics.

    Args:
        address_stats: The existing dictionary of address statistics
        src_addr: The source address to update stats for
        msg_type: The message type to add
        is_broadcast: Whether this is a broadcast message
        is_routed: Whether this is a routed message (if None, determined from msg_type)
        is_forwarded: Whether this is a forwarded packet

    Returns:
        The updated dictionary of address statistics
    """
    # Make a shallow copy of the stats dictionary
    updated_stats = address_stats.copy()

    # Get existing stats for this address or create new ones
    existing_stats = updated_stats.get(src_addr, create_empty_stats())

    # Update the stats
    updated_stats[src_addr] = update_address_stats(
        existing_stats,
        msg_type,
        is_broadcast,
        is_routed,
        is_forwarded,
    )

    return updated_stats
