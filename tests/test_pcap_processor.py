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

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from corona_metrics import CoronaMetricsGenerator
from main import BACnetPcapAnalyzer


class TestBACnetPcapAnalyzer(unittest.TestCase):
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
        analyzer = BACnetPcapAnalyzer()

        for name, path in self.test_pcaps.items():
            with self.subTest(file=name):
                analyzer = BACnetPcapAnalyzer()  # Fresh analyzer for each file
                analyzer.process_pcap(path)

                # Basic assertions to ensure processing happened
                self.assertTrue(
                    len(analyzer.address_stats) > 0,
                    f"No address stats collected for {path}",
                )

    def test_device_cache_population(self):
        """Test that device cache is correctly populated from PCAP files."""
        # Test with forwarded NPDU sample which contains MS/TP devices
        analyzer = BACnetPcapAnalyzer()
        analyzer.process_pcap(self.test_pcaps["forwarded"])

        # Verify device cache has entries
        self.assertTrue(
            len(analyzer.device_cache) > 0, "No devices found in device cache"
        )

        # Check for device ID-based entries
        device_id_entries = [
            k for k in analyzer.device_cache.keys() if k.startswith("device:")
        ]
        self.assertTrue(
            len(device_id_entries) > 0, "No device ID-based entries in device cache"
        )

        # Verify MS/TP device addresses
        mstp_devices = []
        for addr, info in analyzer.device_cache.items():
            if addr.startswith("device:"):
                continue  # Skip device ID entries

            if ":" in addr:
                network, mac = addr.split(":", 1)
                if network != "0":
                    mstp_devices.append(addr)

        self.assertTrue(len(mstp_devices) > 0, "No MS/TP devices found in device cache")

        # Specific device checks for the test file
        # The test file should contain devices 704036 and 930102 with their MS/TP addresses
        device_ids = {info.device_id for _, info in analyzer.device_cache.items()}
        self.assertIn(704036, device_ids, "Expected device ID 704036 not found")
        self.assertIn(930102, device_ids, "Expected device ID 930102 not found")

    def test_message_type_counting(self):
        """Test that message types are correctly counted."""
        analyzer = BACnetPcapAnalyzer()
        analyzer.process_pcap(self.test_pcaps["whois_iam"])

        # Check for WhoIs and IAm message types
        message_types = set()
        for addr, stats in analyzer.address_stats.items():
            message_types.update(stats.message_types.keys())

        self.assertIn(
            "WhoIsRequest", message_types, "WhoIsRequest message type not found"
        )
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
                analyzer = BACnetPcapAnalyzer()
                analyzer.process_pcap(path)

                metrics_gen = CoronaMetricsGenerator(analyzer)
                metrics_gen.generate_metrics()

                # Verify metrics were created
                self.assertTrue(
                    len(metrics_gen.device_metrics) > 0,
                    f"No metrics generated for {path}",
                )

                # Check for some specific metrics based on the test files
                for device_id, data in metrics_gen.device_metrics.items():
                    metrics = data["metrics"]
                    if name == "whois_iam" or name == "forwarded":
                        # These files contain WhoIs and IAm messages
                        self.assertTrue(
                            metrics["whoIsRequestsSent"] > 0
                            or metrics["iAmResponsesSent"] > 0,
                            f"Expected WhoIs or IAm metrics for device {device_id} not found",
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
                    analyzer = BACnetPcapAnalyzer()
                    analyzer.process_pcap(path)

                    metrics_gen = CoronaMetricsGenerator(analyzer)
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
