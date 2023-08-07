import sys
import psutil
import threading
import time

def bytes_to_kb(bytes_value):
    return bytes_value / 1024

def display_new_processes():
    existing_processes = set(psutil.pids())

    print("{:<8} {:<25} {:<40} {:>10} {:>10} {:<25} {:>10} {:>10}".format(
        "PID", "Name", "Command Line", "CPU (%)", "Memory (MB)", "Connection Type", "Sent (KB)", "Recv (KB)"))
    print("-" * 128)

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

            connections = process.connections()
            if connections:
                connection = connections[0]
                conn_type = connection.type
                sent_kb = connection.bytes_sent / 1024  # Convert bytes to KB
                recv_kb = connection.bytes_recv / 1024  # Convert bytes to KB
            else:
                conn_type = "N/A"
                sent_kb = 0
                recv_kb = 0

            print("{:<8} {:<{name_len}} {:<{cmd_len}} {:>10.2f} {:>10.2f} {:<25} {:>10.2f} {:>10.2f}".format(
                pid_str, name, cmdline, cpu_percent, memory_mb, conn_type, sent_kb, recv_kb,
                name_len=max_name_len, cmd_len=max_cmd_len))

        existing_processes = current_processes

def get_memory_details(pid):
    try:
        process = psutil.Process(pid)
        memory_info = process.memory_full_info()

        base_address = hex(memory_info.uss)
        memory_type = "Private" if memory_info.private else "Mapped"
        size_kb = bytes_to_kb(memory_info.rss)
        protection_kb = bytes_to_kb(memory_info.rss)
        use_kb = bytes_to_kb(memory_info.uss)
        total_ws_kb = bytes_to_kb(memory_info.vms)
        private_ws_kb = bytes_to_kb(memory_info.private)
        shareable_ws_kb = total_ws_kb - private_ws_kb

        print(f"Memory Details for Process with PID {pid}:")
        print("Base Address:", base_address)
        print("Type:", memory_type)
        print("Size:", size_kb, "KB")
        print("Protection:", protection_kb, "KB")
        print("Use:", use_kb, "KB")
        print("Total WS:", total_ws_kb, "KB")
        print("Private WS:", private_ws_kb, "KB")
        print("Shareable WS:", shareable_ws_kb, "KB")

    except psutil.NoSuchProcess:
        print(f"No process found with PID {pid}")
    except psutil.AccessDenied:
        print("Access denied. Run the script as an administrator or with appropriate permissions.")

def main():
    display_thread = threading.Thread(target=display_new_processes)
    display_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
