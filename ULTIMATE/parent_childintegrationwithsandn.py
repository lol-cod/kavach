import csv
import psutil
import subprocess


def read_connected_pids_from_csv(file_path):
    connected_pids = []
    with open(file_path, mode="r", newline="", encoding="utf-8") as csv_file:
        csv_reader = csv.reader(csv_file)
        next(csv_reader)  # Skip header row
        for row in csv_reader:
            pid = int(row[0])
            connected_pids.append(pid)
    return connected_pids

def display_process_tree(target_pid):
    try:
        process = psutil.Process(target_pid)
        print("Process Tree:")
        indent = ''
        while True:
            print(indent + f"PID: {process.pid}, Name: {process.name()}")
            children = process.children(recursive=False)
            if len(children) == 0:
                break
            process = children[0]
            indent += '  '
    except psutil.NoSuchProcess:
        print("Process not found.")

def get_signer_information(process_id):
    try:
        process = psutil.Process(process_id)
        process_exe = process.exe()

        if not process_exe:
            print("Process executable path not available.")
            return

        # Use PowerShell to retrieve signer information
        powershell_script = (
            f"Get-AuthenticodeSignature -FilePath '{process_exe}' | "
            "Select-Object -ExpandProperty SignerCertificate | "
            "Format-List"
        )
        
        cmd = ["powershell", "-Command", powershell_script]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Error while retrieving signer information:")
            print(result.stderr)

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print("Unable to retrieve signer information.")


if __name__ == "__main__":
    connected_pids = read_connected_pids_from_csv("connected_processes.csv")
    
    print("Connected PIDs:")
    for index, pid in enumerate(connected_pids):
        print(f"{index + 1}. {pid}")
    
    selected_index = int(input("Select an index to display process tree: ")) - 1
    
    if 0 <= selected_index < len(connected_pids):
        target_pid = connected_pids[selected_index]
        display_process_tree(target_pid)
        get_signer_information(target_pid)
    else:
        print("Invalid index.")
