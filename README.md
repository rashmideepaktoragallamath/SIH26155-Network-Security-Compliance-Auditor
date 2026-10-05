# SIH26155 - Network Security Compliance Auditor

A deterministic, vendor-neutral audit tool for network device security baselines. It inspects Cisco and Juniper configuration files, maps the relevant settings into a common security model, evaluates them against security controls, and produces a risk score with remediation guidance.

The project is implemented as a Streamlit web app and is designed to help security reviewers validate configuration posture quickly and consistently.

## Overview

Network devices often use different configuration syntaxes across vendors. This project normalizes those differences into a single internal model and checks whether key security controls are implemented correctly.

It analyzes:
- Cisco IOS-style configurations
- Juniper Junos `set` syntax
- Juniper Junos curly-brace syntax

It then reports:
- Security score out of 100
- Non-compliant controls
- Controls needing manual review
- Compliant controls
- Vendor-specific remediation commands
- Rollback suggestions
- JSON export of the full audit report

## Features

- Automatic vendor detection
- Multi-vendor parsing for common network security settings
- Common Security Model (CSM) mapping
- Deterministic compliance assessment
- Security scoring and overall risk classification
- Evidence-based findings with matching config lines
- Recommended remediation steps
- Downloadable JSON report
- Sample configurations for testing

## Supported Controls

The auditor checks core hardening requirements such as:

- SSH version 2 enforcement
- Telnet management disabled
- HTTP management disabled
- Remote syslog enabled
- Strong privileged password protection
- No default SNMP community strings
- NTP configuration
- Login banner presence

## How It Works

1. The user uploads a configuration file or pastes a config into the web app.
2. The system identifies the vendor.
3. A parser converts the device-specific syntax into a common security model.
4. A rules engine checks each control against expected values.
5. The result is scored and displayed with evidence and remediation commands.

This is a rule-based compliance engine, not a black-box AI decision maker. The logic is explicit, explainable, and auditable.

## Project Structure

- app.py - Streamlit web interface
- adapters.py - Vendor detection and config parsing
- engine.py - Compliance rules, scoring, and risk evaluation
- samples/ - Example Cisco and Juniper configurations
- requirements.txt - Python dependencies

## Tech Stack

- Python 3
- Streamlit
- Regex-based parsing
- Deterministic rule engine

## Prerequisites

- Python 3.9+
- pip
- Virtual environment recommended

## Installation

```bash
git clone https://github.com/your-username/SIH26155-Network-Security-Compliance-Auditor.git
cd SIH26155-Network-Security-Compliance-Auditor
python -m venv .venv