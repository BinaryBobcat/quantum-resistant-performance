from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import os
import base64
import json
import psutil
import time
import threading
import csv

def monitor_resources(stop_event):
    process = psutil.Process()
    cpu_values = []
    memory_values = []
    
    while not stop_event.is_set():
        cpu_usage = process.cpu_percent(interval=1)
        memory_usage = process.memory_info().rss / (1024 * 1024)  # in MB
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        
        print(f"[{timestamp}] CPU: {cpu_usage:.4f}%, Memory: {memory_usage:.4f} MB")
        
        cpu_values.append(cpu_usage)
        memory_values.append(memory_usage)
    
    return cpu_values, memory_values

def read_from_file(filename):

    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read()) 

def generate_ec_key_pair(curve=ec.SECP256R1()):
    
    # Generate a private/public key
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    
    return private_key, public_key


def hybrid_ec_encrypt(message, recipient_public_key):

    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate an ephemeral EC key pair (sender's temporary key)
    ephemeral_private_key, ephemeral_public_key = generate_ec_key_pair()
    
    # Perform ECDH key exchange to get shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    
    # Derive an AES key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    
    # Generate a random IV for AES-CBC
    iv = os.urandom(16)
    
    # Pad the message to a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
    padded_message = padder(message)
    
    # Encrypt the message with AES
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Serialize the ephemeral public key
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Create a package containing all necessary components
    encryption_package = {
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ephemeral_public_key': base64.b64encode(ephemeral_public_bytes).decode('utf-8')
    }
    
    return json.dumps(encryption_package)

def hybrid_ec_decrypt(encrypted_package, recipient_private_key):

    # Parse the encryption package
    package = json.loads(encrypted_package)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    iv = base64.b64decode(package['iv'])
    ephemeral_public_bytes = base64.b64decode(package['ephemeral_public_key'])
    
    # Load the ephemeral public key
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes)
    
    # Perform ECDH key exchange to get the same shared secret
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    
    # Derive the same AES key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message
    unpadder = lambda s: s[:-s[-1]]
    message = unpadder(padded_message)
    
    return message

def main():
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Create summary results file
    summary_file = "logs/ecc.csv"
    with open(summary_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Run', 'Execution Time (s)', 'Avg CPU (%)', 'Max CPU (%)', 'Avg Memory (MB)', 'Max Memory (MB)'])
    
<<<<<<< Updated upstream
    i = 0

    # looping until all text files have been encrypted and decrypted
    while i != 100:
        i = i + 1
=======
    for run in range(1, 11):
        print(f"\n=== Starting Run {run} of 10 ===")
>>>>>>> Stashed changes
        
        # Create a stop event for the monitoring thread
        stop_event = threading.Event()
        
        # Start the resource monitoring in a separate thread
        cpu_memory_data = [[], []]  # To store CPU and memory values
        monitor_thread = threading.Thread(target=lambda: cpu_memory_data.extend(monitor_resources(stop_event)))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        start_time = time.time()
        
        try:
            # Generate EC key pair (these would be the recipient's long-term keys)
            print("Generating Elliptic Curve key pair...")
            private_key, public_key = generate_ec_key_pair()
            
            i = 0
            while i != 100:
                i = i + 1
                
                filename = "./ciphertexts/"+str(i)
            
                # Encrypt and decrypt the short message
                encrypted_package = hybrid_ec_encrypt(read_from_file(filename), public_key)
                print("Encrypting ciphertext: "+str(i))
            
                hybrid_ec_decrypt(encrypted_package, private_key)
                print("Decrypting ciphertext: "+str(i))
                
        finally:
            # Stop the monitoring thread
            stop_event.set()
            
            # Wait for the thread to finish
            monitor_thread.join(timeout=1)
            
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Run {run} execution time: {execution_time:.4f} seconds")
            
            # Get CPU and memory values from the monitoring thread
            cpu_values = cpu_memory_data[2] if len(cpu_memory_data) > 2 else []
            memory_values = cpu_memory_data[3] if len(cpu_memory_data) > 3 else []
            
            # Calculate statistics if we have data
            if cpu_values and memory_values:
                avg_cpu = sum(cpu_values) / len(cpu_values)
                max_cpu = max(cpu_values)
                avg_memory = sum(memory_values) / len(memory_values)
                max_memory = max(memory_values)
                
                # Write summary to the summary file with 4 decimal places
                with open(summary_file, 'a', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow([run, f"{execution_time:.4f}", f"{avg_cpu:.4f}", f"{max_cpu:.4f}", 
                                      f"{avg_memory:.4f}", f"{max_memory:.4f}"])
                
                # Print summary with 4 decimal places
                print(f"Run {run} stats - Avg CPU: {avg_cpu:.4f}%, Max CPU: {max_cpu:.4f}%, "
                      f"Avg Memory: {avg_memory:.4f} MB, Max Memory: {max_memory:.4f} MB")
            else:
                print("No data collected for statistics calculation")
    
    print("\n=== All runs completed ===")
    print(f"Summary results saved to {summary_file}")

if __name__ == "__main__":
    main()
