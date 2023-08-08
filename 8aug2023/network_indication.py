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

def get_connections_by_pid(process_id):
    connections = psutil.net_connections(kind='inet')

    connections_info = []
    for conn in connections:
        if conn.pid == process_id:
            local_address = f"{conn.laddr[0]}:{conn.laddr[1]}"
            remote_address = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else ""
            is_internet = is_internet_connection(conn.raddr)

            connections_info.append((local_address, remote_address, is_internet))

    return connections_info

if __name__ == "__main__":
    internet_processes = get_processes_with_internet_connections()
    if not internet_processes:
        print("No processes found with active internet connections.")
    else:
        print("Processes with Active Internet Connections:")
        print("{:<8} {:<25} {:<40} {:<20}".format("PID", "Name", "Command Line", "Remote Address"))
        print("-" * 100)
        process_id = None
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
            break  # Only consider the first process in this example
        
        if process_id is not None:
            connections_info = get_connections_by_pid(process_id)
            if not connections_info:
                print("No active connections found for the specified PID.")
            else:
                print("\nActive Connections:")
                print("{:<20} {:<20} {:<15}".format("Local Address", "Remote Address", "Is Internet"))
                print("-" * 65)
                for local_address, remote_address, is_internet in connections_info:
                    print(f"{local_address:<20} {remote_address:<20} {'Yes' if is_internet else 'No'}")
