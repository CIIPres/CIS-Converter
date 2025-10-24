#!/usr/bin/env python3

import csv
import re


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

    # Look for PowerShell commands first (more complex checks)
    ps_commands = re.findall(r'\(Get-ItemProperty[^\)]+\)[^\n]+', audit_text)

    if ps_commands:
        for cmd in ps_commands:
            # Clean up the PowerShell command
            cmd = cmd.replace('\n', ' ').strip()
            rules.append(f"c:powershell {cmd}")
    else:
        # Look for registry paths in format: HKLM\\path:ValueName
        # Need to handle line breaks in the CSV data - they can split registry paths and value names
        # First, join lines that are continuations (don't start with uppercase or number)
        lines = audit_text.split('\n')
        joined_lines = []
        for line in lines:
            line_stripped = line.strip()
            if line_stripped and joined_lines and not line_stripped[0].isupper() and not line_stripped[0].isdigit() and line_stripped[0] not in ['H', '{']:
                # This line is a continuation, append to previous line
                joined_lines[-1] += line_stripped
            else:
                joined_lines.append(line_stripped)

        audit_cleaned = ' '.join(joined_lines)

        # Pattern to match registry paths with value names
        # Format: HKLM\\Path\\To\\Key:ValueName
        # Value names can contain letters, numbers, and underscores
        reg_pattern = r'HKLM\\\\(?:[^:\n]+?):([A-Za-z0-9_]+)'
        matches = re.findall(reg_pattern, audit_cleaned, re.IGNORECASE)

        if matches:
            # Extract the full registry path
            # Find the complete registry path including the value name
            full_matches = re.finditer(r'(HKLM\\\\[^:\n]+?):([A-Za-z0-9_]+)', audit_cleaned, re.IGNORECASE)

            for match in full_matches:
                reg_path = match.group(1)
                value_name = match.group(2)

                # Convert HKLM to HKEY_LOCAL_MACHINE
                reg_path = reg_path.replace('HKLM\\\\', 'HKEY_LOCAL_MACHINE\\')
                reg_path = reg_path.replace('\\\\', '\\')

                # Look for expected value in audit text
                # Common patterns: "value of 1", "set to 0", "REG_DWORD value of 1"
                expected_value = None
                value_patterns = [
                    r'value of (\d+)',
                    r'set to (\d+)',
                    r'REG_DWORD value of (\d+)',
                    r'confirm the value is set to (\d+)'
                ]

                for pattern in value_patterns:
                    value_match = re.search(pattern, audit_text, re.IGNORECASE)
                    if value_match:
                        expected_value = value_match.group(1)
                        break

                # Build the rule
                if expected_value:
                    rules.append(f"r:{reg_path} -> {value_name} -> {expected_value}")
                else:
                    rules.append(f"r:{reg_path} -> {value_name}")

                # Only use the first complete registry path found
                break

    return rules


def clean_text(text):
    """Remove line breaks and extra whitespace from text."""
    if not text:
        return ""
    # Replace line breaks with spaces
    text = text.replace('\n', ' ').replace('\r', ' ')
    # Replace multiple spaces with single space
    text = re.sub(r'\s+', ' ', text)
    # Replace double backslashes with single backslashes (from CSV escaping)
    text = text.replace('\\\\', '\\')
    # Strip leading/trailing whitespace
    return text.strip()


def escape_yaml_string(text):
    """Escape special characters for YAML double-quoted strings."""
    if not text:
        return ""
    # Escape backslashes first (must be done before other escapes)
    text = text.replace('\\', '\\\\')
    # Escape double quotes
    text = text.replace('"', '\\"')
    return text


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

            # Store original policy for comment
            original_policy = policy

            # Clean all text fields to remove line breaks
            policy = clean_text(policy)
            description = clean_text(description)
            rationale = clean_text(rationale)
            impact = clean_text(impact)
            remediation = clean_text(remediation)

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

            # Extract reference URLs and clean them
            ref_urls = re.findall(r'https?://[^\s\n]+', references)
            # Clean each reference URL to remove any line breaks that split them
            cleaned_refs = []
            for ref in ref_urls:
                # Remove any line breaks and join if URL was split
                ref = ref.strip()
                if ref:
                    cleaned_refs.append(ref)
            ref_urls = cleaned_refs

            # Build the check entry with comment
            check = {
                'id': check_id,
                'comment': f"{cis_num} ({profile}) {policy}",  # Comment line
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

        # Write policy section
        f.write("policy:\n")
        f.write('  id: "cis_win11_enterprise"\n')
        f.write('  file: "cis_win11_enterprise.yml"\n')
        f.write('  name: "CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0"\n')
        f.write('  description: "This document provides prescriptive guidance for establishing a secure configuration posture for Microsoft Windows 11. Please note that the rules provide accurate results for Windows 11 Operating Systems with the System language set to English. The SCA policy will work with other languages but the results will be less accurate due to some of the rules that depend on the System language."\n')
        f.write('  references:\n')
        f.write('  - "https://www.cisecurity.org/cis-benchmarks/"\n')

        # Write requirements section
        f.write("requirements:\n")
        f.write('  title: "Check that the Windows platform is Windows 11"\n')
        f.write('  description: "Requirements for running the CIS benchmark Domain Controller under Windows 11"\n')
        f.write('  condition: all\n')  # No quotes for condition
        f.write('  rules:\n')
        f.write(r"  - 'r:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -> ProductName -> r:^Windows 11'" + '\n')

        # Write checks section
        f.write("checks:\n")
        for i, check in enumerate(checks):
            # Write comment above the check
            f.write(f" # {check['comment']}\n")
            f.write(f"- id: {check['id']}\n")
            f.write(f'  title: "{escape_yaml_string(check["title"])}"\n')
            f.write(f'  description: "{escape_yaml_string(check["description"])}"\n')
            f.write(f'  rationale: "{escape_yaml_string(check["rationale"])}"\n')
            f.write(f'  impact: "{escape_yaml_string(check["impact"])}"\n')
            f.write(f'  remediation: "{escape_yaml_string(check["remediation"])}"\n')
            f.write(f'  references:\n')
            for ref in check['references']:
                # Write reference without f-string to avoid escaping backslashes
                f.write("  - '" + ref + "'\n")
            f.write(f'  compliance:\n')
            for comp in check['compliance']:
                for key, values in comp.items():
                    # Format as inline array: - cis: ["1.1", "2.2"]
                    values_str = ', '.join([f'"{v}"' for v in values])
                    f.write(f'  - {key}: [{values_str}]\n')
            f.write(f'  condition: {check["condition"]}\n')  # No quotes for condition
            f.write(f'  rules:\n')
            for rule in check['rules']:
                # Write rule without f-string to avoid escaping backslashes
                f.write("  - '" + rule + "'\n")

            # Add blank line between checks (except after the last one)
            if i < len(checks) - 1:
                f.write('\n')

    print(f"Converted {len(checks)} checks from {csv_file} to {yaml_file}")
    print(f"Check IDs: {base_id} to {check_id - 1}")


if __name__ == '__main__':
    csv_to_yaml(
        'CIS_Microsoft_Intune_for_Windows_11_Benchmark_v4.0.0.csv',
        'CISv4_win11_enterprise.yml'
    )
