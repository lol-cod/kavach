import psutil

def count_process_instances(process_name):
    count = 0
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() == process_name.lower():
            count += 1
    return count

if __name__ == "__main__":
    process_name_to_count = input("Enter the name of the process to count: ")
    instance_count = count_process_instances(process_name_to_count)
    
    if instance_count > 0:
        print(f"Number of instances of '{process_name_to_count}': {instance_count}")
    else:
        print(f"No instances of '{process_name_to_count}' found")

