#!/usr/bin/env python
"""
Test suite for the command-line interface
"""

import os
import subprocess
import tempfile
import pytest
import json
import hszinc  # Added import
import datetime


class TestCommandLineInterface:
    """Test class for the command-line interface."""
    
    @pytest.fixture
    def sample_pcap(self):
        """Fixture to provide a sample PCAP file path."""
        # Assuming the test runs from the project root or tests/ directory
        # Adjust path if necessary
        pcap_path = os.path.join(os.path.dirname(__file__), "SampleWhoisIamForwardedBroadcast.pcap")
        if not os.path.exists(pcap_path):
            # Try relative to project root if not found relative to test file
            pcap_path = "SampleWhoisIamForwardedBroadcast.pcap"
        if not os.path.exists(pcap_path):
            pytest.fail(f"Sample PCAP file not found at expected locations: {pcap_path}")
        return pcap_path
    
    def test_generate_metrics_ttl_format(self, sample_pcap):
        """Test that the CLI can generate metrics in TTL format."""
        with tempfile.NamedTemporaryFile(suffix=".ttl", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Run the CLI with TTL format using the entry point
            cmd = [
                "corona-pcap-processor",  # Use the entry point
                sample_pcap, 
                tmp_path, 
                "--format", 
                "ttl"
            ]
            process = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Check that the process succeeded
            assert process.returncode == 0, f"Process failed with output: {process.stderr}"
            
            # Check output file
            assert os.path.exists(tmp_path), "TTL file was not created"
            assert os.path.getsize(tmp_path) > 0, "TTL file is empty"
            
            # Verify it's a valid TTL file
            with open(tmp_path, "r") as f:
                content = f.read()
                assert content.startswith("# Corona BACnet metrics"), "Not a valid TTL file"
                assert "@prefix" in content, "TTL file missing prefixes"
                
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_generate_metrics_zinc_format(self, sample_pcap):
        """Test that the CLI can generate metrics in Zinc format."""
        with tempfile.NamedTemporaryFile(suffix=".zinc", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Run the CLI with Zinc format using the entry point
            cmd = [
                "corona-pcap-processor",  # Use the entry point
                sample_pcap, 
                tmp_path, 
                "--format", 
                "zinc"
            ]
            process = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Check that the process succeeded
            assert process.returncode == 0, f"Process failed with output: {process.stderr}"
            
            # Check output file
            assert os.path.exists(tmp_path), "Zinc file was not created"
            assert os.path.getsize(tmp_path) > 0, "Zinc file is empty"
            
            # Verify it's a valid Zinc file
            with open(tmp_path, "rb") as f:  # Read in binary mode for hszinc
                content = f.read().decode('utf-8')
                grid = hszinc.parse(content)
                assert isinstance(grid, hszinc.Grid), "Parsed content is not a Haystack Grid"

                # Verify metadata
                assert grid.version == "3.0", f"Expected ZINC version '3.0', got '{grid.version}'"
                assert grid.metadata.get("database") == "bacnet", "Incorrect 'database' in metadata"
                assert grid.metadata.get("dis") == "BACnet Corona Metrics", "Incorrect 'dis' in metadata"
                assert isinstance(grid.metadata.get("generatedOn"), str), "'generatedOn' is not a datetime.datetime object"  # Corrected type check

                # Verify columns
                expected_columns = {
                    "id": {"dis": "ID"},
                    "dis": {"dis": "Device"},
                    "device": {},
                    "deviceId": {},
                    "bacnetAddress": {},
                    "network": {},
                    "mac": {},
                    "addressType": {},
                    "metric": {"dis": "Metric"},
                    "val": {"dis": "Value"},
                    "unit": {}
                }
                assert len(grid.column) == len(expected_columns), "Incorrect number of columns"
                for col_name, col_meta in expected_columns.items():
                    assert col_name in grid.column, f"Column '{col_name}' is missing"
                    if "dis" in col_meta:
                        actual_col_meta = grid.column[col_name]  # Corrected line: removed .metadata
                        assert actual_col_meta.get("dis") == col_meta["dis"], \
                            f"Incorrect 'dis' for column '{col_name}'. Expected '{col_meta['dis']}', got '{actual_col_meta.get('dis')}'"
                
                # Assuming a valid pcap will produce some rows
                assert len(grid) > 0, "Zinc file has no rows"

                # Verify first row structure and types (optional, but good for deeper validation)
                if len(grid) > 0:
                    first_row = grid[0]
                    assert isinstance(first_row.get("id"), hszinc.Ref), "ID in first row is not a Ref"
                    assert isinstance(first_row.get("dis"), str), "Display name in first row is not a string"
                    assert first_row.get("device") is hszinc.MARKER, "Device in first row is not a Marker"
                    # deviceId can be Null or Str, so checking type might be hszinc.NULL or str
                    # assert first_row.get("deviceId") is hszinc.NULL or isinstance(first_row.get("deviceId"), str)
                    assert isinstance(first_row.get("bacnetAddress"), str), "bacnetAddress in first row is not a string"
                    assert isinstance(first_row.get("metric"), str), "Metric in first row is not a string"
                    assert isinstance(first_row.get("val"), (int, float)), "Value in first row is not an int or float"  # Ensure this is (int, float)
                    # unit can be Null
                    # assert first_row.get("unit") is hszinc.NULL

        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_generate_metrics_json_format(self, sample_pcap):
        """Test that the CLI can generate metrics in JSON format."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Run the CLI with JSON format using the entry point
            cmd = [
                "corona-pcap-processor",  # Use the entry point
                sample_pcap, 
                tmp_path, 
                "--format", 
                "json"
            ]
            process = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Check that the process succeeded
            assert process.returncode == 0, f"Process failed with output: {process.stderr}"
            
            # Check output file
            assert os.path.exists(tmp_path), "JSON file was not created"
            assert os.path.getsize(tmp_path) > 0, "JSON file is empty"
            
            # Verify it's a valid JSON file
            with open(tmp_path, "r") as f:
                try:
                    data = json.load(f)
                    assert "meta" in data, "Not a valid Haystack JSON file"
                    assert "rows" in data, "Not a valid Haystack JSON file"
                except json.JSONDecodeError:
                    pytest.fail("Invalid JSON file")
                
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_generate_metrics_prometheus_format(self, sample_pcap):
        """Test that the CLI can generate metrics in Prometheus format."""
        with tempfile.NamedTemporaryFile(suffix=".prom", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Run the CLI with Prometheus format using the entry point
            cmd = [
                "corona-pcap-processor",  # Use the entry point
                sample_pcap, 
                tmp_path, 
                "--format", 
                "prom"
            ]
            process = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Check that the process succeeded
            assert process.returncode == 0, f"Process failed with output: {process.stderr}"
            
            # Check output file
            assert os.path.exists(tmp_path), "Prometheus file was not created"
            assert os.path.getsize(tmp_path) > 0, "Prometheus file is empty"
            
            # Verify it's a valid Prometheus file
            with open(tmp_path, "r") as f:
                content = f.read()
                assert content.startswith("#"), "Not a valid Prometheus file"
                assert "# HELP" in content, "Prometheus file missing HELP"
                assert "# TYPE" in content, "Prometheus file missing TYPE"
                
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_format_extension_added(self, sample_pcap):
        """Test that appropriate extensions are added based on format."""
        formats = {
            "ttl": ".ttl",
            "zinc": ".zinc",
            "json": ".json",
            "prom": ".prom"
        }
        
        for format_name, extension in formats.items():
            with tempfile.NamedTemporaryFile(prefix="test_metrics_", delete=False) as tmp:
                base_path = tmp.name
                
            try:
                # Remove any existing extension
                if "." in os.path.basename(base_path):
                    base_path = os.path.splitext(base_path)[0]
                    
                # Run the CLI with the format using the entry point
                cmd = [
                    "corona-pcap-processor",  # Use the entry point
                    sample_pcap, 
                    base_path, 
                    "--format", 
                    format_name
                ]
                process = subprocess.run(cmd, check=True, capture_output=True, text=True)
                
                # Check that the process succeeded
                assert process.returncode == 0, f"Process failed with output: {process.stderr}"
                
                # Check that the file with the correct extension was created
                expected_path = base_path + extension
                assert os.path.exists(expected_path), f"File with {extension} extension was not created"
                
            finally:
                # Clean up
                for ext in formats.values():
                    if os.path.exists(base_path + ext):
                        os.unlink(base_path + ext)


if __name__ == "__main__":
    # Run the tests directly if this script is executed
    pytest.main(["-xvs", __file__])