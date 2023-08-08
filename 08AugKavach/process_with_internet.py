import psutil

def is_internet_connection(remote_address):
    return bool(remote_address)

def get_processes_with_internet_connections():
    connections = psutil.net_connections(kind='inet')

    process_connections = {}
    for conn in connections:
        if conn.raddr:
            process_id = conn.pid
            try:
                process = psutil.Process(process_id)
                process_connections.setdefault(process_id, []).append((process, conn))
            except psutil.NoSuchProcess:
                # Process might have terminated between getting connections and process information
                continue
            except psutil.AccessDenied:
                # Access Denied for the process information, skip it
                continue

    return process_connections

if __name__ == "__main__":
    internet_processes = get_processes_with_internet_connections()
    if not internet_processes:
        print("No processes found with active internet connections.")
    else:
        print("Processes with Active Internet Connections:")
        print("{:<8} {:<25} {:<40} {:<20}".format("PID", "Name", "Command Line", "Remote Address"))
        print("-" * 100)
        for process_id, connections in internet_processes.items():
            for process, conn in connections:
                try:
                    name = process.name()
                    cmdline = " ".join(process.cmdline())
                    remote_address = f"{conn.raddr[0]}:{conn.raddr[1]}"
                    print(f"{process_id:<8} {name:<25} {cmdline:<40} {remote_address:<20}")
                except psutil.AccessDenied:
                    # Access Denied while accessing process information, skip it
                    continue