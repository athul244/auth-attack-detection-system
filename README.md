# Authentication Attack Detection and Investigation System

Detects and investigates authentication attacks (brute force,
password spraying, credential stuffing) from login logs.

## Goals
- Ingest authentication logs (SSH, Windows, web app)
- Detect suspicious patterns with rule-based logic
- Raise alerts and support investigation (who, when, from where)

## Planned Features
- [ ] Log parser
- [ ] Brute force detection
- [ ] Password spraying detection
- [ ] Alert output (CLI/CSV/dashboard)
- [ ] Investigation report per attacker IP

## Tech Stack
TBD (Python, Wazuh/ELK, etc.)

## Status
🚧 In progress