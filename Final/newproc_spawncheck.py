import sys
import psutil
import ctypes

def bytes_to_kb(bytes_value):
    return bytes_value / 1024

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def display_new_processes():
    existing_processes = set(psutil.pids())

    print("{:<8} {:<25} {:<40} {:<15} {:<20} {:>10} {:>10}".format(
        "PID", "Name", "Command Line", "User", "Instance", "CPU (%)", "Memory (MB)"))
    print("-" * 128)
    sys.stdout.flush()

    while True:
        current_processes = set(psutil.pids())
        new_processes = current_processes - existing_processes

        max_name_len = max_cmd_len = 25
        for pid in new_processes:
            process = psutil.Process(pid)
            name_len = len(process.name())
            cmd_len = len(" ".join(process.cmdline()))
            max_name_len = max(max_name_len, name_len)
            max_cmd_len = max(max_cmd_len, cmd_len)

        for pid in new_processes:
            process = psutil.Process(pid)

            pid_str = str(process.pid)
            name = process.name()
            cmdline = " ".join(process.cmdline())
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_mb = process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

            try:
                user = process.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                user = "N/A"
            
            try:
                instance = process.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                instance = "N/A"

            admin_status = "Admin" if is_admin() else "Regular User"

            print("{:<8} {:<{name_len}} {:<{cmd_len}} {:<15} {:<20} {:>10.2f} {:>10.2f}".format(
                pid_str, name, cmdline, user, instance, cpu_percent, memory_mb,
                name_len=max_name_len, cmd_len=max_cmd_len))
            
            print("Running as:", admin_status)
            sys.stdout.flush()

        existing_processes = current_processes

if __name__ == "__main__":
    display_new_processes()
