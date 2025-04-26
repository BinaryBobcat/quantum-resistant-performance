# System Monitoring Scripts

This repository contains two Python scripts for monitoring system resources.

## Requirements

- Python 3.6+
- psutil library (`pip install psutil`)

## Scripts

### 1. process_monitor.py

Monitors the resource usage of the current Python process only.

### 2. system_monitor.py

Monitors the resource usage of the entire system.

## Usage

1. To monitor the current Python process only:

`python process_monitor.py`

2. To monitor system-wide resources:

`python system_monitor.py`

You can adjust the following parameters in both scripts:
- interval: How frequently to collect data (in seconds)
- duration: How long to run the monitoring (in seconds), or set to None to run until stopped with Ctrl+C