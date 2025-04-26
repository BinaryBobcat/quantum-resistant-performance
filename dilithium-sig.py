from dilithium_py.dilithium import Dilithium2
import base64
import psutil
import time
import threading
import csv
import os

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

# Generate a keypair
pk, sk = Dilithium2.keygen()

i = 0

# looping until all text files have been encrypted and decrypted
while i != 100:
    i = i + 1
        
    filename = "./ciphertexts/"+str(i)

def main():
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Create summary results file
    summary_file = "logs/dilithium-sig.csv"
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
            # Generate a keypair
            pk, sk = Dilithium2.keygen()
            
            i = 0
            while i != 100:
                i = i + 1
                    
                filename = "./ciphertexts/"+str(i)
                
                ct = read_from_file(filename)

                # Convert message to bytes if it's a string
                if isinstance(ct, str):
                    ct = ct.encode('utf-8')

                # Sign the message
                signature = Dilithium2.sign(sk, ct)
                signed_message = signature + ct
                print("Ciphertext signed: "+str(i))

                valid = Dilithium2.verify(pk, ct, signature)

                if valid:
                    print("Signature "+str(i)+" verified")
                else:
                    print("Signature "+str(i)+" NOT verified")
                
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