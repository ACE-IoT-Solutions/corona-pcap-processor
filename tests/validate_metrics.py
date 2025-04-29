#!/usr/bin/env python
"""
Validate Corona metrics files against the Corona standard.
Uses the validate_model.py script from the Corona standard repository.
"""

import argparse
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Validate Corona metrics files against the Corona standard."
    )
    parser.add_argument(
        "metrics_file", help="The metrics file to validate (TTL format)"
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze the metrics file and print statistics",
    )
    args = parser.parse_args()

    # Determine the path to the Corona standard repository
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.normpath(os.path.join(current_dir, ".."))
    corona_standard_dir = os.path.normpath(
        os.path.join(project_root, "corona-standard")
    )

    if not os.path.exists(corona_standard_dir):
        print(f"Error: Corona standard repository not found at {corona_standard_dir}")
        print(
            "Please make sure the Corona standard repository is available at this location."
        )
        sys.exit(1)

    # Validate the metrics file using the validate_model.py script
    validator_script = os.path.join(corona_standard_dir, "validate_model.py")
    if not os.path.exists(validator_script):
        print(f"Error: Validator script not found at {validator_script}")
        print(
            "Please make sure the Corona standard repository contains validate_model.py."
        )
        sys.exit(1)

    # Build the command
    cmd = [sys.executable, validator_script]
    if args.analyze:
        cmd.append("--analyze")
    cmd.append(args.metrics_file)

    # Run the validation
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Validation failed with exit code {e.returncode}")
        sys.exit(e.returncode)
    except FileNotFoundError:
        print(f"Error: Python interpreter not found at {sys.executable}")
        sys.exit(1)


if __name__ == "__main__":
    main()
