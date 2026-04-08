# Architecture

<!-- TODO: High-level system diagram showing Kali VM (server + agent) and Cloud Dashboard -->

## Overview

The NIDS-IPS system consists of three main components:

1. **Central Server** — Flask REST API + Web Dashboard (deployed online)
2. **Detection Agent** — Scapy-based packet capture + IPS (runs on Kali VM)
3. **Attack Simulator** — Tools for generating test traffic

## System Diagram

```
┌──────────────────────────────────────────────────┐
│              Kali Linux VM                       │
│                                                  │
│  ┌──────────────┐     ┌───────────────────────┐  │
│  │  NIDS Agent   │────▶│   Central Server      │  │
│  │  (Scapy +     │     │   (Flask + SQLite)    │  │
│  │   iptables)   │◀────│                       │  │
│  └──────────────┘     └───────────┬───────────┘  │
│                                   │              │
└───────────────────────────────────┼──────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  Cloud Dashboard   │
                          │  (Render / PA)     │
                          │  Accessible from   │
                          │  anywhere          │
                          └───────────────────┘
```
