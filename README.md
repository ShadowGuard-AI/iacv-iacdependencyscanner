# iacv-IacDependencyScanner
Scans Infrastructure-as-Code (IaC) templates for external dependencies (e.g., Docker images, scripts fetched from URLs, modules from external registries) and analyzes their security posture by checking for known vulnerabilities in those dependencies. Provides a risk assessment based on the severity and number of vulnerabilities found. - Focused on Analyzes Infrastructure-as-Code (IaC) definitions (e.g., Terraform, CloudFormation, Kubernetes manifests) for security misconfigurations and compliance violations *before* they are deployed. Validates that the IaC adheres to defined security policies and best practices (e.g., proper IAM permissions, network segmentation, resource constraints). Supports common IaC languages and provides human-readable reports highlighting potential risks.

## Install
`git clone https://github.com/ShadowStrikeHQ/iacv-iacdependencyscanner`

## Usage
`./iacv-iacdependencyscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `--dependency-check`: No description provided
- `--security-check`: No description provided
- `--policy-file`: No description provided
- `--log-level`: No description provided

## License
Copyright (c) ShadowStrikeHQ
