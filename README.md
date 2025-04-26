# System Monitoring Scripts

This repository contains two Python scripts for monitoring system resources.

## Requirements

- Python 3.6+
- pip install requirements.txt

## Scripts

### 1. process_monitor.py

Monitors the resource usage of the current Python process only.

### 2. system_monitor.py

Monitors the resource usage of the entire system.

### 3. encryption scripts

Each encryption algorithm tested has their own python script that will encrypt/decrypt or sign/verify the full directory of text files


## Usage

1. To monitor the current Python process only:

`python process_monitor.py`

2. To monitor system-wide resources:

`python system_monitor.py`

You can adjust the following parameters in both scripts:
- interval: How frequently to collect data (in seconds)
- duration: How long to run the monitoring (in seconds), or set to None to run until stopped with Ctrl+C
