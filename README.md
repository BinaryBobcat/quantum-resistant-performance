# Quantum Resistance Performance Scripts

This repository contains Python scripts for quantum and non-quantum resistant encryption algorithms along with scripts to monitoring system resources to determine algorithm performance.

## Requirements

- Python 3.6+
- pip install requirements.txt
- https://github.com/janmojzis/python-mceliece.git
- https://github.com/tprest/falcon.py

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
