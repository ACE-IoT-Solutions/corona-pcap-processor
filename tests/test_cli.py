#!/usr/bin/env python
"""
Test suite for the command-line interface
"""

import os
import sys
import subprocess
import tempfile
import pytest
import json

# Add parent directory to path to access modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestCommandLineInterface:
    """Test class for the command-line interface."""
    
    @pytest.fixture
    def sample_pcap(self):
        """Fixture to provide a sample PCAP file path."""
        return "SampleWhoisIamForwardedBroadcast.pcap"
    
    def test_generate_metrics_ttl_format(self, sample_pcap):
        """Test that the CLI can generate metrics in TTL format."""
        with tempfile.NamedTemporaryFile(suffix=".ttl", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Run the CLI with TTL format
            cmd = [
                sys.executable, 
                "generate_corona_metrics.py", 
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
            # Run the CLI with Zinc format
            cmd = [
                sys.executable, 
                "generate_corona_metrics.py", 
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
            with open(tmp_path, "r") as f:
                content = f.read()
                assert 'ver:"3.0"' in content, "Not a valid Zinc file"
                
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_generate_metrics_json_format(self, sample_pcap):
        """Test that the CLI can generate metrics in JSON format."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Run the CLI with JSON format
            cmd = [
                sys.executable, 
                "generate_corona_metrics.py", 
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
            # Run the CLI with Prometheus format
            cmd = [
                sys.executable, 
                "generate_corona_metrics.py", 
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
                    
                # Run the CLI with the format
                cmd = [
                    sys.executable, 
                    "generate_corona_metrics.py", 
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