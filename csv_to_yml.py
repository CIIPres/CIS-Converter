#!/usr/bin/env python3

import csv
import re
import yaml

def parse_cis_controls(cis_controls_text):
    """Parse CIS Controls text and extract v8 and v7 controls."""
    v8_controls = []
    v7_controls = []

    if not cis_controls_text:
        return v8_controls, v7_controls

    # Split by v8 and v7 sections
    v8_match = re.search(r'v8\s*(.*?)(?:v7|$)', cis_controls_text, re.DOTALL)
    v7_match = re.search(r'v7\s*(.*?)$', cis_controls_text, re.DOTALL)

    if v8_match:
        v8_text = v8_match.group(1).strip()
        # Extract control numbers like "4.8", "0.0"
        v8_nums = re.findall(r'^([\d.]+)', v8_text, re.MULTILINE)
        v8_controls = [num for num in v8_nums if num and num != "0.0"]

    if v7_match:
        v7_text = v7_match.group(1).strip()
        # Extract control numbers
        v7_nums = re.findall(r'^([\d.]+)', v7_text, re.MULTILINE)
        v7_controls = [num for num in v7_nums if num]

    return v8_controls, v7_controls


def create_registry_rule(cis_num, audit_text):
    """Create registry or powershell rule from audit text."""
    rules = []

    if not audit_text:
        return rules

    # Look for HKLM registry paths
    reg_paths = re.findall(r'(HKLM[^\n]+)', audit_text, re.IGNORECASE)

    # Look for PowerShell commands
    ps_commands = re.findall(r'\(Get-ItemProperty[^\)]+\)[^\n]+', audit_text)

    if ps_commands:
        for cmd in ps_commands:
            # Clean up the PowerShell command
            cmd = cmd.replace('\n', ' ').strip()
            # Extract the expected value
            value_match = re.search(r'-> (\d+)', cmd)
            if value_match:
                expected_val = value_match.group(1)
                rules.append(f"c:powershell {cmd}")
    elif reg_paths:
        # For simple registry checks, create a basic rule
        for path in reg_paths[:1]:  # Use first path found
            # Extract registry path and value name
            parts = path.split(':')
            if len(parts) >= 2:
                reg_path = parts[0].replace('HKLM\\', 'HKEY_LOCAL_MACHINE\\')
                value_name = parts[1].strip() if len(parts) > 1 else None

                if value_name:
                    rules.append(f"r:{reg_path} -> {value_name}")

    return rules


def csv_to_yaml(csv_file, yaml_file, base_id=26000):
    """Convert CIS CSV to Wazuh YAML format."""

    checks = []
    check_id = base_id

    with open(csv_file, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)

        for row in reader:
            cis_num = row.get('CIS #', '').strip()
            policy = row.get('Policy', '').strip()
            scored = row.get('Scored', '').strip()
            profile = row.get('Type', '').strip()
            description = row.get('Description', '').strip()
            rationale = row.get('Rationale', '').strip()
            impact = row.get('Impact', '').strip()
            remediation = row.get('Remediation', '').strip()
            audit = row.get('Audit', '').strip()
            references = row.get('References', '').strip()
            cis_controls = row.get('CIS Controls', '').strip()

            # Skip if no CIS number or policy
            if not cis_num or not policy:
                continue

            # Parse CIS Controls
            v8_controls, v7_controls = parse_cis_controls(cis_controls)

            # Create compliance section
            compliance = [{'cis': [cis_num]}]
            if v8_controls:
                compliance.append({'cis_csc_v8': v8_controls})
            if v7_controls:
                compliance.append({'cis_csc_v7': v7_controls})

            # Create rules from audit text
            rules = create_registry_rule(cis_num, audit)

            # If no rules were created, add a placeholder comment
            if not rules:
                rules = [f"# TODO: Implement check for CIS {cis_num}"]

            # Extract reference URLs
            ref_urls = re.findall(r'https?://[^\s\n]+', references)

            # Build the check entry
            check = {
                'id': check_id,
                'title': policy,
                'description': description if description else policy,
                'rationale': rationale if rationale else "See CIS Benchmark for details.",
                'impact': impact if impact else "See CIS Benchmark for details.",
                'remediation': remediation if remediation else "See CIS Benchmark for details.",
                'references': ref_urls if ref_urls else [],
                'compliance': compliance,
                'condition': 'all',
                'rules': rules
            }

            checks.append(check)
            check_id += 1

    # Create the YAML structure
    yaml_content = {
        'policy': {
            'id': 'cis_win11_enterprise',
            'file': 'cis_win11_enterprise.yml',
            'name': 'CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0',
            'description': 'This document provides prescriptive guidance for establishing a secure configuration posture for Microsoft Windows 11. Please note that the rules provide accurate results for Windows 11 Operating Systems with the System language set to English. The SCA policy will work with other languages but the results will be less accurate due to some of the rules that depend on the System language.',
            'references': ['https://www.cisecurity.org/cis-benchmarks/']
        },
        'requirements': {
            'title': 'Check that the Windows platform is Windows 11',
            'description': 'Requirements for running the CIS benchmark Domain Controller under Windows 11',
            'condition': 'all',
            'rules': [
                "r:HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion -> ProductName -> r:^Windows 11"
            ]
        },
        'checks': checks
    }

    # Write YAML file with custom formatting
    with open(yaml_file, 'w', encoding='utf-8') as f:
        # Write header comment
        f.write("# Security Configuration Assessment\n")
        f.write("# CIS Checks for Windows 11 Enterprise\n")
        f.write("# Copyright (C) 2015, Wazuh Inc.\n")
        f.write("#\n")
        f.write("# This program is free software; you can redistribute it\n")
        f.write("# and/or modify it under the terms of the GNU General Public\n")
        f.write("# License (version 2) as published by the FSF - Free Software\n")
        f.write("# Foundation\n")
        f.write("#\n")
        f.write("# Based on:\n")
        f.write("# Center for Internet Security Benchmark v4.0.0 for Microsoft Windows 11 Enterprise - 10-22-2025\n\n")

        # Write YAML content
        yaml.dump(yaml_content, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)

    print(f"Converted {len(checks)} checks from {csv_file} to {yaml_file}")
    print(f"Check IDs: {base_id} to {check_id - 1}")


if __name__ == '__main__':
    csv_to_yaml(
        'CIS_Microsoft_Intune_for_Windows_11_Benchmark_v4.0.0.csv',
        'CISv4_win11_enterprise.yml'
    )
