import psutil

def bytes_to_kb(bytes_value):
    return bytes_value / 1024

def get_memory_details(pid):
    try:
        process = psutil.Process(pid)
        memory_maps = process.memory_maps(grouped=False)

        print(f"Memory Details for Process with PID {pid}:")
        print("{:<15} {:<15} {:<15} {:<10}".format("Base Address", "Size (KB)", "Type", "Protection"))
        print("-" * 70)

        for region in memory_maps:
            base_address = region.addr
            size_kb = bytes_to_kb(region.rss)
            protection = region.rss
            mem_type = "Unknown"

            # Attempt to categorize memory regions based on common characteristics
            if "[stack]" in region.path:
                mem_type = "Stack"
            elif "[heap]" in region.path:
                mem_type = "Heap"
            elif region.path == "":
                # Memory mapped files usually have no associated path, but they might include .nls files
                if ".nls" in region.path_lower:
                    mem_type = "Mapped File (.nls)"

            prot_str = get_protection_string(region.perms)  # Get R/W/C protection string

            print("{:<15} {:<15} {:<15} {:<10}".format(base_address, size_kb, mem_type, prot_str))

    except psutil.NoSuchProcess:
        print(f"No process found with PID {pid}")
    except psutil.AccessDenied:
        print("Access denied. Run the script as an administrator or with appropriate permissions.")

def get_protection_string(permissions):
    # Interpret the permission flags to display in R/W/C format
    prot_str = ""
    prot_str += "R" if "r" in permissions else "-"
    prot_str += "W" if "w" in permissions else "-"
    prot_str += "C" if "c" in permissions else "-"
    return prot_str

if __name__ == "__main__":
    target_pid = 5556  # Set the target PID to 5556
    get_memory_details(target_pid)
