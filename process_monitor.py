import time
import psutil
import os

def monitor_resources(interval=1.0, duration=None):
    process = psutil.Process(os.getpid())
    
    # Give the process a moment to stabilize
    process.cpu_percent()
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
            
            # Get CPU and memory usage
            cpu = process.cpu_percent()
            memory = process.memory_info().rss / (1024 * 1024)  # Convert to MB
            
            # Print results
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
monitor_resources(interval=0.5, duration=10)
