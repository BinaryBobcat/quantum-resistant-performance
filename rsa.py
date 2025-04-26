from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
        # memory_usage = process.memory_info().vms / 1024 # in KB
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        
        print(f"[{timestamp}] CPU: {cpu_usage:.3f}%, Memory: {memory_usage:.6f} MB")
        
        cpu_values.append(cpu_usage)
        memory_values.append(memory_usage)
    
    return cpu_values, memory_values

def read_from_file(filename):
    
    # open and read the whole plaintext file
    with open(filename, 'r') as f:
        return str(f.read()) 

def generate_rsa_key_pair(key_size=2048):

    # generate private key with e = 65537 and defined bit length
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # make a public key based on private key
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):

    # make a serialized version of the private and public key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

def hybrid_encrypt(message, public_key):

    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate a random AES key and IV
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)
    
    # Pad the message to a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
    padded_message = padder(message)
    
    # Encrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create a package containing all necessary components
    encryption_package = {
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }
    
    return json.dumps(encryption_package)

def hybrid_decrypt(encrypted_package, private_key):

    # Parse the encryption package
    package = json.loads(encrypted_package)
    encrypted_message = base64.b64decode(package['encrypted_message'])
    encrypted_key = base64.b64decode(package['encrypted_key'])
    iv = base64.b64decode(package['iv'])
    
    # Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the message with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message
    unpadder = lambda s: s[:-s[-1]]
    message = unpadder(padded_message)
    
    return message

def main():
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Generate RSA key pair
    print("Generating RSA key pair...")
    private_key, public_key = generate_rsa_key_pair(2048)

    i = 0

    # Loop until all text files have been encrypted/decrypted
    while i != 100:
        i = i + 1

    # Create summary results file
    summary_file = "logs/rsa.csv"
    with open(summary_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Run', 'Execution Time (s)', 'Avg CPU (%)', 'Max CPU (%)', 'Avg Memory (MB)', 'Max Memory (MB)'])
    
    for run in range(1, 11):
        print(f"\n=== Starting Run {run} of 10 ===")

        # Create a stop event for the monitoring thread
        stop_event = threading.Event()
        
        # Start the resource monitoring in a separate thread
        cpu_memory_data = [[], []]  # To store CPU and memory values
        monitor_thread = threading.Thread(target=lambda: cpu_memory_data.extend(monitor_resources(stop_event)))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        start_time = time.time()
        
        try:
            # Generate RSA key pair
            print("Generating RSA key pair...")
            private_key, public_key = generate_rsa_key_pair(2048)

            i = 0
            while i != 100:
                i = i + 1
                
                filename = "./ciphertexts/"+str(i)
                # Encrypt the message
                encrypted_package = hybrid_encrypt(read_from_file(filename), public_key)
                print("Encrypting ciphertext: "+str(i))


                # Decrypt the message
                hybrid_decrypt(encrypted_package, private_key)
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
                    csvwriter.writerow([run, f"{execution_time:.4f}", f"{avg_cpu:.3f}", f"{max_cpu:.3f}", 
                                      f"{avg_memory:.6f}", f"{max_memory:.6f}"])
                
                # Print summary with 4 decimal places
                print(f"Run {run} stats - Avg CPU: {avg_cpu:.3f}%, Max CPU: {max_cpu:.3f}%, "
                      f"Avg Memory: {avg_memory:.6f} MB, Max Memory: {max_memory:.6f} MB")
            else:
                print("No data collected for statistics calculation")
    
    print("\n=== All runs completed ===")
    print(f"Summary results saved to {summary_file}")

if __name__ == "__main__":
    main()
