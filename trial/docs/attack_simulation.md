# Attack Simulation Guide

<!-- TODO: How to generate test attacks for NIDS-IPS testing -->

## Prerequisites

- Separate attacker VM (Ubuntu/Kali) or use the same Kali VM
- nmap, hping3, curl installed

## Available Attack Scripts

<!-- TODO: Document each attack script -->

| Script | Attack Type | Tool Used |
|--------|------------|-----------|
| port_scan.sh | Port Scanning | nmap |
| sql_injection.sh | SQL Injection | curl |
| xss_attack.sh | XSS | curl |
| dos_attack.sh | DoS Flood | hping3 |
| combined_attack.sh | All attacks | mixed |
