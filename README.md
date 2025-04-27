# Quantum Resistant Algorithm Performance

![ChatGPT Image Apr 26, 2025 at 05_36_54 PM](https://github.com/user-attachments/assets/d7f784eb-2e97-4b51-a14d-ac0cbdaa7e0b)

This project provides a comprehensive benchmarking suite for comparing various cryptographic algorithms, including both traditional and post-quantum cryptographic methods. The suite measures execution time, CPU usage, and memory consumption across multiple runs to provide reliable performance metrics.

## Overview

The benchmarking suite includes implementations for:

### Traditional Cryptographic Algorithms
- **AES-256** (Advanced Encryption Standard with 256-bit keys)
- **3DES** (Triple Data Encryption Standard)
- **ChaCha20** (Stream Cipher)
- **RSA** (Rivest–Shamir–Adleman)
- **ECC** (Elliptic Curve Cryptography)

### Post-Quantum Cryptographic Algorithms
- **Kyber-512** (Lattice-based KEM)
- **McEliece** (Code-based Encryption)
- **SPHINCS** (Stateless Hash-based Signatures)
- **Falcon** (Lattice-based Signatures)
- **Dilithium** (Lattice-based Signatures)

## Installation

To set up the benchmarking environment:

1. Clone this repository
2. Install the required dependencies:
   ```
   pip3 install -r requirements.txt
   
   sudo apt-get install libmceliece1
   ```

## Required Dependencies

The project requires the following Python packages:
- cryptography (≥41.0.0)
- psutil (≥5.9.0)
- kyber-py (≥0.5.0)
- pyspx (≥0.5.0)
- dilithium-py (≥0.5.0)
- numpy (≥2.2.5)
- crypto (≥1.4.1)
- pycryptodome (≥3.22.0)

Additional libraries may be required for specific algorithms:
- python-mceliece (for McEliece algorithm)
- falcon.py (for Falcon signatures)

## Directory Structure

```
├── algs/                 # External algorithm implementations
│   ├── python-mceliece/
│   └── falcon.py/
├── ciphertexts/          # Test files (numbered 1-100)
├── logs/                 # Directory for benchmark results
├── *.py                  # Algorithm implementation files
└── requirements.txt      # Required dependencies
```

## Benchmark Methodology

Each script:

1. Performs 10 complete runs 
2. For each run:
   - Processes 100 text files from the `ciphertexts/` directory
   - Encrypts and decrypts (or signs and verifies) each file
   - Monitors CPU usage and memory consumption in real-time
   - Records execution time for the complete process
3. Saves detailed results to CSV files in the `logs/` directory

The benchmark records:
- Execution time (seconds)
- Average CPU usage (%)
- Maximum CPU usage (%)
- Average memory usage (MB)
- Maximum memory usage (MB)

## Running the Benchmarks

To run an individual benchmark:

```bash
python3 algorithm-name.py
```

Each benchmark will:
1. Create a `logs/` directory if it doesn't exist
2. Generate cryptographic keys
3. Process all test files in the `ciphertexts/` directory
4. Save results to `logs/algorithm-name.csv`

## Analyzing Results

After running the benchmarks, you can compare the performance of different algorithms by examining the CSV files in the `logs/` directory. These files contain detailed metrics for each run, allowing for statistical analysis of performance characteristics.

## Example Result

<img width="917" alt="image" src="https://github.com/user-attachments/assets/c7d3599a-e48a-4f56-8c49-9c8d2c243751" />

## Algorithms Overview

### Symmetric Encryption
- **AES-256**: Block cipher with 256-bit keys using CBC mode
- **3DES**: Block cipher using CBC mode
- **ChaCha20**: Stream cipher

### Asymmetric Encryption
- **RSA**: Traditional public-key cryptography (2048-bit keys)
- **ECC**: Elliptic curve cryptography using SECP256R1 curve
- **Kyber-512**: Lattice-based post-quantum key encapsulation mechanism
- **McEliece**: Code-based post-quantum encryption

### Digital Signatures
- **Dilithium**: Lattice-based post-quantum signature scheme
- **Falcon**: Lattice-based post-quantum signature scheme
- **SPHINCS**: Hash-based post-quantum signature scheme
