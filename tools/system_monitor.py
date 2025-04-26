import time
import psutil

def monitor_system_resources(interval=1.0, duration=None):
    # Give the system a moment to stabilize
    psutil.cpu_percent()
    time.sleep(0.1)
    
    start_time = time.time()
    print("=" * 60)
    print("Time Elapsed  |  CPU %  |  Memory (MB)")
    print("-" * 60)
    
    try:
        while True:
            # Get current elapsed time
            current_time = time.time()
            elapsed = current_time - start_time
            
            # Get system-wide CPU and memory usage
            cpu = psutil.cpu_percent()
            memory = psutil.virtual_memory().used / (1024 * 1024)  # Convert to MB
            
            # Print results in the same format as the original script
            print(f"{elapsed:.2f}s         {cpu:.1f}%     {memory:.2f} MB")
            
            if duration and elapsed >= duration:
                break
                
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped manually")
    finally:
        end_time = time.time()
        total_time = end_time - start_time
        print("=" * 60)
        print(f"Total monitoring time: {total_time:.2f} seconds")

# Interval is the amount of time to wait until the next collection of data
# Duration is the total amount of time
monitor_system_resources(interval=0.5, duration=10)