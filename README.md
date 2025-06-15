# Nmap Firewall Bypass Tool

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-brightgreen.svg)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A specialized Nmap integration tool designed to overcome restrictive firewalls and tcpwrapped responses during penetration testing engagements.

## Overview

The Nmap Firewall Bypass Tool extends Nmap's capabilities with advanced evasion techniques, adaptive scanning strategies, and specialized methods for handling problematic ports. It's designed for penetration testers who need to maximize port discovery in environments with strict network controls.

![Tool Screenshot](docs/images/screenshot.png)

## Features

- **Advanced Firewall Evasion**: Multiple techniques including packet fragmentation, source port manipulation, and decoy scanning
- **Adaptive Scanning**: Analyzes firewall behavior and tailors scan strategies accordingly
- **tcpwrapped Resolution**: Specialized handling of ports that return tcpwrapped responses
- **Scalable Scanning**: Efficiently handles large target lists with parallel processing
- **Comprehensive Reporting**: Detailed output with actionable insights for manual follow-up
- **Multi-phase Scanning**: Progressive methodology to maximize discovery while minimizing scan time

## Requirements

- Python 3.6+
- Nmap 7.80+
- Standard Python libraries (no external dependencies)

## Installation

```bash
# Clone the repository
git clone https://github.com/elementalsouls/nmap-firewall-bypass.git

# Navigate to the directory
cd nmap-firewall-bypass

# Make the scripts executable
chmod +x nmap_firewall_bypass.py