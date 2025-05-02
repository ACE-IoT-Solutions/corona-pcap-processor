"""
Debugging utilities for BACnet PCAP Analyzer.
"""

from typing import Any, List



def debug_frame(frame: Any, debug_level: int = 1) -> List[str]:
    """Generate debug information about a frame.

    Args:
        frame: The frame to debug
        debug_level: The debug level (1-3, higher means more verbose)

    Returns:
        A list of debug message strings
    """
    debug_msgs = []
    debug_msgs.append("----- Frame Debug -----")

    # Basic frame info
    if hasattr(frame, "_number"):
        debug_msgs.append(f"Frame Number: {frame._number}")

    if hasattr(frame, "_timestamp"):
        debug_msgs.append(f"Timestamp: {frame._timestamp}")

    # IP information
    if hasattr(frame, "ipv4") and frame.ipv4:
        debug_msgs.append(
            f"IPv4: src={frame.ipv4.source_address}, dst={frame.ipv4.destination_address}"
        )

    # UDP information
    if hasattr(frame, "udp") and frame.udp:
        debug_msgs.append(
            f"UDP: src_port={frame.udp.source_port}, dst_port={frame.udp.destination_port}"
        )

    # BVLCI information
    if hasattr(frame, "bvlci") and frame.bvlci:
        debug_msgs.append(
            f"BVLCI: type={frame.bvlci.bvlciType}, function={frame.bvlci.bvlciFunction}"
        )

    # NPDU info
    if hasattr(frame, "npdu") and frame.npdu:
        debug_msgs.append(f"NPDU: {type(frame.npdu).__name__}")

        # More detailed NPDU info if debug level > 1
        if debug_level > 1:
            for attr in dir(frame.npdu):
                if not attr.startswith("_") and attr not in (
                    "encode",
                    "decode",
                    "copy",
                    "dict_contents",
                ):
                    try:
                        value = getattr(frame.npdu, attr)
                        debug_msgs.append(f"  NPDU.{attr}: {value}")
                    except:
                        pass

        # Source address in NPDU
        if hasattr(frame.npdu, "npduSADR") and frame.npdu.npduSADR:
            debug_msgs.append("  NPDU Source Address:")
            sadr = frame.npdu.npduSADR

            if hasattr(sadr, "addrType"):
                debug_msgs.append(f"    Type: {sadr.addrType}")

            if hasattr(sadr, "addrNet"):
                debug_msgs.append(f"    Network: {sadr.addrNet}")

            if hasattr(sadr, "addrAddr"):
                mac_bytes = sadr.addrAddr
                mac_hex = "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else "None"
                debug_msgs.append(f"    MAC: {mac_hex} (hex: {sadr.addrAddr!r})")

                if hasattr(sadr, "addrNet"):
                    debug_msgs.append(f"    BACnet Address: {sadr.addrNet}:{mac_hex}")

    # BVLL information
    if hasattr(frame, "bvll") and frame.bvll:
        debug_msgs.append(f"BVLL type: {type(frame.bvll).__name__}")

        # More detailed BVLL info if debug level > 1
        if debug_level > 1:
            for attr in dir(frame.bvll):
                if not attr.startswith("_") and attr not in (
                    "encode",
                    "decode",
                    "copy",
                    "dict_contents",
                ):
                    try:
                        value = getattr(frame.bvll, attr)
                        debug_msgs.append(f"  BVLL.{attr}: {value}")
                    except:
                        pass

        # NPDU in BVLL
        if hasattr(frame.bvll, "npdu") and frame.bvll.npdu:
            debug_msgs.append(f"  BVLL.NPDU: {type(frame.bvll.npdu).__name__}")

            # More detailed NPDU info if debug level > 2
            if debug_level > 2:
                for attr in dir(frame.bvll.npdu):
                    if not attr.startswith("_") and attr not in (
                        "encode",
                        "decode",
                        "copy",
                        "dict_contents",
                    ):
                        try:
                            value = getattr(frame.bvll.npdu, attr)
                            debug_msgs.append(f"    BVLL.NPDU.{attr}: {value}")
                        except:
                            pass

            # Source address in NPDU
            if hasattr(frame.bvll.npdu, "npduSADR") and frame.bvll.npdu.npduSADR:
                debug_msgs.append("    BVLL.NPDU Source Address:")
                sadr = frame.bvll.npdu.npduSADR

                if hasattr(sadr, "addrType"):
                    debug_msgs.append(f"      Type: {sadr.addrType}")

                if hasattr(sadr, "addrNet"):
                    debug_msgs.append(f"      Network: {sadr.addrNet}")

                if hasattr(sadr, "addrAddr"):
                    mac_bytes = sadr.addrAddr
                    mac_hex = "".join(f"{b:02x}" for b in mac_bytes) if mac_bytes else "None"
                    debug_msgs.append(f"      MAC: {mac_hex} (hex: {sadr.addrAddr!r})")

                    if hasattr(sadr, "addrNet"):
                        debug_msgs.append(f"      BACnet Address: {sadr.addrNet}:{mac_hex}")

            # APDU in NPDU
            if hasattr(frame.bvll.npdu, "apdu") and frame.bvll.npdu.apdu:
                debug_msgs.append(f"    BVLL.NPDU.APDU: {type(frame.bvll.npdu.apdu).__name__}")

                # More detailed APDU info if debug level > 2
                if debug_level > 2:
                    for attr in dir(frame.bvll.npdu.apdu):
                        if not attr.startswith("_") and attr not in (
                            "encode",
                            "decode",
                            "copy",
                            "dict_contents",
                        ):
                            try:
                                value = getattr(frame.bvll.npdu.apdu, attr)
                                debug_msgs.append(f"      BVLL.NPDU.APDU.{attr}: {value}")
                            except:
                                pass

    # APDU information
    if hasattr(frame, "apdu") and frame.apdu:
        debug_msgs.append(f"APDU type: {type(frame.apdu).__name__}")

        # More detailed APDU info if debug level > 1
        if debug_level > 1:
            for attr in dir(frame.apdu):
                if not attr.startswith("_") and attr not in (
                    "encode",
                    "decode",
                    "copy",
                    "dict_contents",
                ):
                    try:
                        value = getattr(frame.apdu, attr)
                        debug_msgs.append(f"  APDU.{attr}: {value}")
                    except:
                        pass

    # Raw BVLL data in hex for debugging
    if hasattr(frame, "bvll") and frame.bvll and hasattr(frame.bvll, "pduData"):
        debug_msgs.append("  Raw BVLL pduData (hex):")
        data = frame.bvll.pduData

        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_values = " ".join(f"{b:02x}" for b in chunk)
            ascii_values = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            debug_msgs.append(f"    {i:04x}: {hex_values:<47} | {ascii_values}")

    debug_msgs.append("------------------------")
    return debug_msgs


def print_debug_frame(frame: Any, debug_level: int = 1) -> None:
    """Print debug information about a frame.

    Args:
        frame: The frame to debug
        debug_level: The debug level (1-3, higher means more verbose)
    """
    for msg in debug_frame(frame, debug_level):
        print(msg)
