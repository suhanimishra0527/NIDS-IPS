# Attack Simulator

Tools for generating test attacks against the NIDS-IPS system.

## Prerequisites
- nmap, hping3, curl
- Separate VM or same Kali VM

## Usage

```bash
# Run all attacks
bash scripts/combined_attack.sh <TARGET_IP>

# Individual attacks
bash scripts/port_scan.sh <TARGET_IP>
bash scripts/sql_injection.sh <TARGET_IP>
```
