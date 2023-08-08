import psutil

def print_process_info(process, depth=0):
    indent = "  " * depth
    print(f"{indent}PID: {process.pid}, Name: {process.name()}, CMD: {' '.join(process.cmdline())}")

def traverse_process_tree(process, depth=0):
    print_process_info(process, depth)
    for child in process.children(recursive=False):
        traverse_process_tree(child, depth + 1)

def create_process_tree(process_id):
    try:
        process = psutil.Process(process_id)
        traverse_process_tree(process)
    except psutil.NoSuchProcess:
        print("Process not found.")

if __name__ == "__main__":
    target_pid = int(input("Enter the target process PID: "))
    create_process_tree(target_pid)
