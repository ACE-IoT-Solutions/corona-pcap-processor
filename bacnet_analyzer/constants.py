"""
Constants and configuration for BACnet PCAP Analyzer.
"""

from enum import Enum
from typing import Dict, Final, Set

from bacpypes3.apdu import apdu_types


class ServiceChoice(Enum):
    """BACnet service choices."""
    I_AM = 0
    I_HAVE = 1
    WHO_HAS = 7
    WHO_IS = 8


# Mapping of service choices to standard message type names
SERVICE_CHOICE_TO_TYPE: Final[Dict[int, str]] = {
    ServiceChoice.I_AM.value: "IAmRequest",
    ServiceChoice.I_HAVE.value: "IHaveRequest",
    ServiceChoice.WHO_HAS.value: "WhoHasRequest",
    ServiceChoice.WHO_IS.value: "WhoIsRequest",
}


class ServiceChoiceMapping:
    """Utilities for working with BACnet service choices."""
    
    @staticmethod
    def get_message_type(service_choice: int) -> str:
        """Get the standard message type name for a service choice.
        
        Args:
            service_choice: The numeric service choice value (0-255)
            
        Returns:
            The standard message type name, or None if not recognized
        """
        return SERVICE_CHOICE_TO_TYPE.get(service_choice)
    
    @staticmethod
    def is_recognized(service_choice: int) -> bool:
        """Check if the service choice is recognized by this analyzer.
        
        Args:
            service_choice: The numeric service choice value (0-255)
            
        Returns:
            True if the service choice is recognized, False otherwise
        """
        return service_choice in SERVICE_CHOICE_TO_TYPE


# Set of message types that indicate routed messages
ROUTED_MESSAGE_TYPES: Final[Set[str]] = {
    "ForwardedNPDU",
    "RouterToNetwork",
    "NetworkToRouter",
}