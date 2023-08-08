from subprocess import call
def open_py_file():
    call(["python", "process_with_internet.py"])

open_py_file()

import psutil
import socket

def is_internet_connection(remote_address):
    # Check if the remote address is set (i.e., the connection is to the internet)
    return bool(remote_address)

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
    process_id = int(input("Enter the PID of the process you want to examine: "))
    
    connections_info = get_connections_by_pid(process_id)
    if not connections_info:
        print("No active connections found for the specified PID.")
    else:
        print("Active Connections:")
        print("{:<20} {:<20} {:<15}".format("Local Address", "Remote Address", "Is Internet"))
        print("-" * 65)
        for local_address, remote_address, is_internet in connections_info:
            print(f"{local_address:<20} {remote_address:<20} {'Yes' if is_internet else 'No'}")