## Quick Start

This page provides quick examples to get started with the Nmap Firewall Bypass Tool.

### Basic Scan
```bash
python nmap_firewall_bypass.py 192.168.1.1
```

### Scan Multiple Targets
```bash
python nmap_firewall_bypass.py targets.txt -t 10
```

### Evasion Levels
```bash
python nmap_firewall_bypass.py 192.168.1.1 -e 3
```

### CIDR Range Scans
```bash
python nmap_firewall_bypass.py 10.0.0.0/24
```
