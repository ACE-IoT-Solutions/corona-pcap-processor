#!/usr/bin/env python
"""
Test suite for BACnet PCAP processor and Corona metrics generator.
"""

import os
import sys
import tempfile
import unittest

# Add parent directory to path to access modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import from new refactored modules
from bacnet_analyzer import BACnetAnalyzer
from bacnet_analyzer.corona_metrics import CoronaMetricsGenerator


class TestBACnetAnalyzer(unittest.TestCase):
    """Test cases for the BACnet PCAP analyzer."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_pcaps = {
            "whois_iam": "sample-whois-iam.pcap",
            "forwarded": "SampleWhoisIamForwardedBroadcast.pcap",
            "sample": "sample-pcap.pcap",
        }

        # Make sure test files exist
        for name, path in self.test_pcaps.items():
            self.assertTrue(os.path.exists(path), f"Test PCAP file {path} not found")

    def test_basic_packet_processing(self):
        """Test that the analyzer can process PCAP files without errors."""
        for name, path in self.test_pcaps.items():
            with self.subTest(file=name):
                analyzer = BACnetAnalyzer()  # Fresh analyzer for each file
                results = analyzer.analyze_pcap(path)

                # Basic assertions to ensure processing happened
                self.assertTrue(
                    len(results.address_stats) > 0,
                    f"No address stats collected for {path}",
                )

    def test_device_cache_population(self):
        """Test that device cache is correctly populated from PCAP files."""
        # Test with sample files
        analyzer = BACnetAnalyzer()
        results = analyzer.analyze_pcap(self.test_pcaps["forwarded"])

        # Verify device cache has entries
        self.assertTrue(len(results.device_cache) > 0, "No devices found in device cache")

        # Check for device ID-based entries
        device_id_entries = [k for k in results.device_cache.keys() if k.startswith("device:")]
        self.assertTrue(len(device_id_entries) > 0, "No device ID-based entries in device cache")

        # Check that devices have valid BACnet addresses
        for addr, info in results.device_cache.items():
            if addr.startswith("device:"):
                continue  # Skip device ID entries

            # Verify that the address contains a network number and MAC part
            self.assertIn(":", addr, f"Invalid BACnet address format for {addr}")

            # Check that device_info contains required fields
            self.assertTrue(hasattr(info, "device_id"), "Device info missing device_id")
            self.assertTrue(hasattr(info, "bacnet_address"), "Device info missing bacnet_address")

        # Check for IP-based devices (which our sample files contain)
        ip_devices = []
        for addr, info in results.device_cache.items():
            if addr.startswith("device:"):
                continue  # Skip device ID entries

            if ":" in addr:
                network, mac = addr.split(":", 1)
                if network == "0" and "." in mac:  # IP address format
                    ip_devices.append(addr)

        self.assertTrue(len(ip_devices) > 0, "No IP-based devices found in device cache")

    def test_message_type_counting(self):
        """Test that message types are correctly counted."""
        analyzer = BACnetAnalyzer()
        results = analyzer.analyze_pcap(self.test_pcaps["whois_iam"])

        # Check for WhoIs and IAm message types
        message_types = set()
        for addr, stats in results.address_stats.items():
            message_types.update(stats.message_types.keys())

        self.assertIn("WhoIsRequest", message_types, "WhoIsRequest message type not found")
        self.assertIn("IAmRequest", message_types, "IAmRequest message type not found")


class TestCoronaMetricsGenerator(unittest.TestCase):
    """Test cases for the Corona metrics generator."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_pcaps = {
            "whois_iam": "sample-whois-iam.pcap",
            "forwarded": "SampleWhoisIamForwardedBroadcast.pcap",
            "sample": "sample-pcap.pcap",
        }

    def test_metrics_generation(self):
        """Test that metrics are generated correctly from PCAP analysis."""
        for name, path in self.test_pcaps.items():
            with self.subTest(file=name):
                analyzer = BACnetAnalyzer()
                results = analyzer.analyze_pcap(path)

                metrics_gen = CoronaMetricsGenerator(results)
                metrics_gen.generate_metrics()

                # Verify metrics were created
                self.assertTrue(
                    len(metrics_gen.device_metrics) > 0,
                    f"No metrics generated for {path}",
                )

                # Check for basic required metrics for each device
                for device_id, data in metrics_gen.device_metrics.items():
                    metrics = data["metrics"]

                    # Each device should have at least packet counts
                    self.assertTrue(
                        "totalBacnetMessagesSent" in metrics and "packetsReceived" in metrics,
                        f"Basic packet metrics missing for device {device_id}",
                    )

                    # Validate that metrics have the expected structure
                    self.assertTrue(
                        isinstance(metrics["totalBacnetMessagesSent"], int),
                        f"Expected numeric value for metrics for {device_id}",
                    )

    def test_ttl_export(self):
        """Test TTL export functionality."""
        for name, path in self.test_pcaps.items():
            with self.subTest(file=name):
                # Create a temporary file for the TTL output
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".ttl")
                temp_file.close()

                try:
                    # Generate and export metrics
                    analyzer = BACnetAnalyzer()
                    results = analyzer.analyze_pcap(path)

                    metrics_gen = CoronaMetricsGenerator(results)
                    metrics_gen.generate_metrics()
                    metrics_gen.export_ttl(temp_file.name)

                    # Verify file was created and has content
                    self.assertTrue(
                        os.path.exists(temp_file.name),
                        f"TTL file not created for {path}",
                    )
                    self.assertTrue(
                        os.path.getsize(temp_file.name) > 0,
                        f"TTL file is empty for {path}",
                    )

                    # Read file content to verify basic TTL structure
                    with open(temp_file.name, "r") as f:
                        content = f.read()
                        self.assertIn(
                            "@prefix corona:",
                            content,
                            "Corona prefix not found in TTL file",
                        )

                        # Looking for either format depending on rdflib's serialization
                        network_interface_found = (
                            "a corona:NetworkInterfaceMetric" in content
                            or "corona:NetworkInterfaceMetric" in content
                        )
                        self.assertTrue(
                            network_interface_found,
                            "NetworkInterfaceMetric type not found in TTL file",
                        )
                finally:
                    # Clean up temporary file
                    if os.path.exists(temp_file.name):
                        os.unlink(temp_file.name)


if __name__ == "__main__":
    unittest.main()
