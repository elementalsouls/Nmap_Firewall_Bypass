# Nmap Firewall Bypass Tool

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-brightgreen.svg)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A specialized Nmap integration tool designed to overcome restrictive firewalls and tcpwrapped responses during penetration testing engagements.

## Overview

The Nmap Firewall Bypass Tool extends Nmap's capabilities with advanced evasion techniques, adaptive scanning strategies, and specialized methods for handling problematic ports.

## Quick Start

```bash
# Basic scan with moderate evasion
python nmap_firewall_bypass.py 192.168.1.1

# Scan multiple targets with aggressive evasion
python nmap_firewall_bypass.py targets.txt -e 3 -t 10

# Quick scan of a network range
python nmap_firewall_bypass.py 10.0.0.0/24 -q -t 15
```

## Usage

### Command Syntax

```
python nmap_firewall_bypass.py [targets] [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `targets` | Target specification: IP address, hostname, CIDR range, or file containing targets (one per line) |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output-dir DIR` | Output directory for scan results | `nmap_results` |
| `-t, --threads N` | Number of concurrent threads | `5` |
| `-q, --quick` | Quick mode: Only scan top ports | `False` |
| `-e, --evasion {1,2,3}` | Evasion level: 1=basic, 2=moderate, 3=aggressive | `2` |
| `--tcp-only` | Skip UDP scanning | `False` |

## Advanced Usage

### Scanning with Different Evasion Levels

#### Basic Evasion (Level 1)
```bash
python nmap_firewall_bypass.py 192.168.1.1 -e 1
```
Uses minimal evasion techniques (packet fragmentation). Fastest option but less effective against sophisticated firewalls.

#### Moderate Evasion (Level 2 - Default)
```bash
python nmap_firewall_bypass.py 192.168.1.1 -e 2
```
Uses multiple evasion techniques including fragmentation and source port manipulation. Good balance between speed and effectiveness.

#### Aggressive Evasion (Level 3)
```bash
python nmap_firewall_bypass.py 192.168.1.1 -e 3
```
Uses all available evasion techniques including decoys, data length randomization, and timing modifications. Slowest but most effective against restrictive firewalls.

### Scanning Multiple Targets

```bash
# From a file
python nmap_firewall_bypass.py targets.txt -o scan_results

# Multiple IPs on command line
python nmap_firewall_bypass.py 192.168.1.1,192.168.1.2,192.168.1.3

# CIDR notation
python nmap_firewall_bypass.py 192.168.1.0/24
```

### Performance Tuning

```bash
# Fast scan of critical servers
python nmap_firewall_bypass.py critical_servers.txt -q -t 15

# Thorough scan with resource control
python nmap_firewall_bypass.py sensitive_target.com -e 3 -t 2
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for authorized penetration testing and security research purposes only. Usage against targets without explicit permission is illegal. The author assumes no liability for misuse.
