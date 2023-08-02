import psutil
import socket

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except psutil.NoSuchProcess:
        return "N/A"

def get_all_network_connections():
    connections = psutil.net_connections(kind='inet')

    states_mapping = {
        psutil.CONN_ESTABLISHED: 'ESTABLISHED',
        psutil.CONN_SYN_SENT: 'SYN_SENT',
        psutil.CONN_SYN_RECV: 'SYN_RECV',
        psutil.CONN_FIN_WAIT1: 'FIN_WAIT1',
        psutil.CONN_FIN_WAIT2: 'FIN_WAIT2',
        psutil.CONN_TIME_WAIT: 'TIME_WAIT',
        psutil.CONN_CLOSE: 'CLOSE',
        psutil.CONN_CLOSE_WAIT: 'CLOSE_WAIT',
        psutil.CONN_LAST_ACK: 'LAST_ACK',
        psutil.CONN_LISTEN: 'LISTEN',
        psutil.CONN_CLOSING: 'CLOSING',
    }

    print("{:<30} {:<20} {:<20} {:<15} {:<10}".format("Process Name", "Local Address", "Remote Address", "State", "Protocol"))
    print("-" * 105)

    for conn in connections:
        local_address = f"{conn.laddr[0]}:{conn.laddr[1]}" if conn.laddr else "N/A"
        remote_address = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "N/A"
        state = states_mapping.get(conn.status, "UNKNOWN")
        connection_type = socket.SOCK_STREAM if conn.type == socket.SOCK_STREAM else socket.SOCK_DGRAM
        process_name = get_process_name(conn.pid)

        print("{:<30} {:<20} {:<20} {:<15} {:<10}".format(process_name, local_address, remote_address, state, connection_type))

if __name__ == "__main__":
    get_all_network_connections()
