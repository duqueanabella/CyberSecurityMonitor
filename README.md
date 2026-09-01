# Cybersecurity Monitoring System

## Overview

A defensive cybersecurity monitoring system for Windows that collects live system
data via PowerShell, evaluates it against detection rules in Python, and logs
events to a SQLite database. Built as a hands-on portfolio project to apply and
understand real detection concepts, not just theory.

## Features (current)

- Collects real running processes and active network connections from the live system
- Flags processes by known suspicious names and by suspicious file locations (e.g. Temp, Downloads)
- Flags network connections to known suspicious ports and unusually high per-process connection volume
- Excludes local loopback traffic to avoid false positives
- Logs every scan (threats and clean scans alike) to a persistent SQLite database
- Automated test suite (pytest) covering detection logic and database functions

## Features (planned)

- Web dashboard (HTML/CSS/JavaScript) to visualize events and alerts
- C++ component for lower-level process monitoring
- Machine learning-based anomaly detection

## Technologies

**In use:** Python, PowerShell, SQLite, Git/GitHub
**Planned:** HTML, CSS, JavaScript, C++

## Project Structure

- `collector/` — PowerShell scripts that gather system/network data
- `detection/` — Python detection engine (rules, alerts, main entry point)
- `database/` — SQLite database logic
- `dashboard/` — Web dashboard (in progress)
- `cpp/` — Planned C++ component
- `tests/` — Automated tests

## Usage

```powershell
.venv\Scripts\Activate.ps1
python detection\main.py
```

## Running Tests

```powershell
pytest -v
```


