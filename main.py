#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import re
import yaml
import json
from jsonschema import validators

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Lists external dependencies in IaC templates (YAML or JSON) and validates a template against a JSON Schema policy file. It does not check dependencies against any vulnerability database and gives no risk assessment."
    )
    parser.add_argument(
        "iac_file",
        help="Path to the Infrastructure-as-Code (IaC) file (YAML or JSON, e.g., a Kubernetes manifest or a Terraform .tf.json file)."
    )
    parser.add_argument(
        "--dependency-check",
        action="store_true",
        help="Enable external dependency check (Docker images, URLs, etc.)."
    )
    parser.add_argument(
        "--security-check",
        action="store_true",
        help="Validate the IaC file against the JSON Schema policy given with --policy-file."
    )
    parser.add_argument(
        "--policy-file",
        help="Path to the security policy file (YAML or JSON). Required for security checks."
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)."
    )

    return parser


def load_iac_file(iac_file_path):
    """
    Loads and parses the IaC file. Supports YAML and JSON formats.

    Args:
        iac_file_path (str): Path to the IaC file.

    Returns:
        dict: The parsed IaC data as a dictionary.
        None: If the file cannot be loaded or parsed.
    """
    try:
        with open(iac_file_path, 'r') as f:
            if iac_file_path.endswith(('.yaml', '.yml')):
                try:
                    iac_data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    logging.error(f"Error parsing YAML file: {e}")
                    return None
            elif iac_file_path.endswith('.json'):
                try:
                    iac_data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing JSON file: {e}")
                    return None
            else:
                logging.error("Unsupported file format.  Only YAML and JSON are supported.")
                return None

        if not isinstance(iac_data, dict) and iac_data is not None:  # None check for empty files
            logging.error("The IaC file does not contain a valid dictionary structure.")
            return None

        return iac_data

    except FileNotFoundError:
        logging.error(f"IaC file not found: {iac_file_path}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading the IaC file: {e}")
        return None



def check_external_dependencies(iac_data):
    """
    Checks the IaC data for external dependencies like Docker images and scripts from URLs.
    This is a simplified example and needs to be extended based on the IaC type.

    Args:
        iac_data (dict): The parsed IaC data.

    Returns:
        list: A list of identified external dependencies.
    """
    dependencies = []
    if iac_data is None:
        return dependencies

    def find_dependencies(data):
        if isinstance(data, dict):
            for value in data.values():
                find_dependencies(value)
        elif isinstance(data, list):
            for item in data:
                find_dependencies(item)
        elif isinstance(data, str):
            if _is_external_dependency(data):
                dependencies.append(data)

    find_dependencies(iac_data)
    return dependencies


_REGISTRY_MARKERS = ("docker.io", "ghcr.io", "quay.io", "amazonaws.com", "gcr.io", "azurecr.io")
_IMAGE_REF = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+([:@][A-Za-z0-9._:-]+)?$")
_IMAGE_NAME_TAG = re.compile(r"^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$")


def _is_external_dependency(value):
    """
    Tests one string as an external dependency: a known registry host
    (docker.io, ghcr.io, quay.io, an ECR amazonaws.com host with or
    without a containers segment, gcr.io, azurecr.io), a script URL
    (.sh, .ps1, or .py, with any query string or fragment stripped
    before the suffix test), a git or registry module source string,
    or a Docker Hub shorthand image reference such as nginx:latest or
    sentinel/app:1.0.
    """
    text = value.strip()
    lowered = text.lower()
    bare = lowered.split("?", 1)[0].split("#", 1)[0]

    if any(marker in lowered for marker in _REGISTRY_MARKERS):
        return True
    if lowered.startswith(("http://", "https://")) and bare.endswith((".sh", ".ps1", ".py")):
        return True  # potential for running code on install
    if lowered.startswith(("git::", "github.com/", "git@")):
        return True
    if "://" not in lowered and (_IMAGE_REF.match(text) or _IMAGE_NAME_TAG.match(text)):
        return True
    return False


def load_policy_file(policy_file_path):
    """
    Loads and parses the security policy file (YAML or JSON).

    Args:
        policy_file_path (str): Path to the policy file.

    Returns:
        dict: The parsed policy data as a dictionary.
        None: If the file cannot be loaded or parsed.
    """
    try:
        with open(policy_file_path, 'r') as f:
            if policy_file_path.endswith(('.yaml', '.yml')):
                try:
                    policy_data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    logging.error(f"Error parsing YAML file: {e}")
                    return None
            elif policy_file_path.endswith('.json'):
                try:
                    policy_data = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing JSON file: {e}")
                    return None
            else:
                logging.error("Unsupported policy file format.  Only YAML and JSON are supported.")
                return None

        if not isinstance(policy_data, dict):
            logging.error("The policy file does not contain a valid dictionary structure.")
            return None

        return policy_data

    except FileNotFoundError:
        logging.error(f"Policy file not found: {policy_file_path}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading the policy file: {e}")
        return None


def validate_security_configuration(iac_data, policy_data):
    """
    Validates the IaC configuration against the provided security policy using JSON Schema.
    This is a basic example and requires a proper schema tailored to the IaC and policy format.

    Args:
        iac_data (dict): The parsed IaC data.
        policy_data (dict): The parsed security policy data (JSON Schema).

    Returns:
        list: A list of security violations found.  Empty list if no violations.
    """
    violations = []

    if iac_data is None or policy_data is None:
        raise ValueError("Security validation not performed: the IaC data or the policy data failed to load.")

    # Check the schema itself first. An invalid schema raises
    # jsonschema's SchemaError here, so a policy that cannot be applied
    # never reads as a clean pass in main.
    validator_class = validators.validator_for(policy_data)
    validator_class.check_schema(policy_data)

    errors = sorted(
        validator_class(policy_data).iter_errors(iac_data),
        key=lambda e: e.json_path,
    )
    for e in errors:
        logging.warning(f"Security violation found: {e.message} at {e.json_path}")
        violations.append(f"{e.message} at {e.json_path}")

    if not violations:
        logging.info("Security validation successful. No violations found.")

    return violations


def main():
    """
    Main function to execute the IaC dependency and security scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    # Input validation: Check if the IaC file exists
    if not os.path.isfile(args.iac_file):
        logging.error(f"Error: IaC file '{args.iac_file}' does not exist.")
        sys.exit(1)

    # A run with neither check flag would check nothing; refuse it
    # instead of exiting 0 in silence.
    if not args.dependency_check and not args.security_check:
        logging.error("Error: No check was requested. Pass --dependency-check or --security-check; nothing was checked.")
        sys.exit(2)

    # Check if policy file exists, if security check is enabled.
    if args.security_check and not args.policy_file:
        logging.error("Error: --policy-file must be specified when --security-check is enabled.")
        sys.exit(1)

    # Load the IaC file
    iac_data = load_iac_file(args.iac_file)

    if iac_data is None:
        sys.exit(1)

    # Perform dependency check if enabled
    if args.dependency_check:
        logging.info("Checking for external dependencies...")
        dependencies = check_external_dependencies(iac_data)
        if dependencies:
            print("External Dependencies Found:")
            for dep in dependencies:
                print(f"- {dep}")
        else:
            print("No external dependencies found.")

    # Perform security check if enabled
    if args.security_check:
        logging.info("Performing security validation...")
        policy_data = load_policy_file(args.policy_file)

        if policy_data is None:
            sys.exit(1)

        try:
            violations = validate_security_configuration(iac_data, policy_data)
        except Exception as e:
            logging.error(f"Security validation could not be performed: {e}")
            sys.exit(1)

        if violations:
            print("Security Violations Found:")
            for violation in violations:
                print(f"- {violation}")
            sys.exit(1) # exit code = 1 indicates failure.
        else:
            print("No security violations found.")

if __name__ == "__main__":
    main()

# Example Usage:
# python iac_scanner.py my_terraform.tf.json --dependency-check --security-check --policy-file security_policy.json
# python iac_scanner.py kubernetes_manifest.yaml --dependency-check
# python iac_scanner.py cloudformation.yml --security-check --policy-file cf_policy.json --log-level DEBUG