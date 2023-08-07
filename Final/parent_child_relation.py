import psutil

# Function to get the parent process ID, name, and path of a given process
def get_parent_process_info(process_id):
    try:
        parent = psutil.Process(process_id)
        return parent.ppid(), parent.name(), parent.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, "", ""

# Function to get the path of a process by its process ID
def get_process_path(process_id):
    try:
        process = psutil.Process(process_id)
        return process.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return("Access denied for this PID: " + process_id)


if __name__ == "__main__":
    process_name = "notepad.exe"  # Replace "notepad.exe" with the name of the target process

    target_process = None
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() == process_name.lower():
            target_process = process
            break

    if target_process is None:
        print(f"Process not found: {process_name}")
    else:
        process_id = target_process.info['pid']
        process_name = target_process.info['name']
        process_path = get_process_path(process_id)
        parent_process_id, parent_process_name, parent_process_path = get_parent_process_info(process_id)

        print("List of all processes with their Process IDs, Names, and Paths:")


        print("\nTarget Process Information:")
        print(f"Process Name: {process_name}")
        print(f"Process ID: {process_id}")
        print(f"Process Path: {process_path}")
        print(f"Parent Process ID: {parent_process_id}")
        print(f"Parent Process Name: {parent_process_name}")
        print(f"Parent Process Path: {parent_process_path}")
