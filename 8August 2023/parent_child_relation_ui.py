import tkinter as tk
from tkinter import ttk
import psutil

def get_parent_process_info(process_id):
    try:
        parent = psutil.Process(process_id)
        return parent.ppid(), parent.name(), parent.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, "", ""

def get_process_path(process_id):
    try:
        process = psutil.Process(process_id)
        return process.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Access denied for this PID: " + str(process_id)

def find_and_display_process():
    process_name = process_name_entry.get()
    target_process = None

    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() == process_name.lower():
            target_process = process
            break

    if target_process is None:
        result_label.config(text=f"Process not found: {process_name}")
    else:
        process_id = target_process.info['pid']
        process_name = target_process.info['name']
        process_path = get_process_path(process_id)
        parent_process_id, parent_process_name, parent_process_path = get_parent_process_info(process_id)

        result_label.config(text="Target Process Information:\n" +
                                 f"Process Name: {process_name}\n" +
                                 f"Process ID: {process_id}\n" +
                                 f"Process Path: {process_path}\n" +
                                 f"Parent Process ID: {parent_process_id}\n" +
                                 f"Parent Process Name: {parent_process_name}\n" +
                                 f"Parent Process Path: {parent_process_path}")

# Create the main window
root = tk.Tk()
root.title("Process Information")

# Create and place GUI elements
process_name_label = ttk.Label(root, text="Enter Process Name:")
process_name_label.pack(pady=10)

process_name_entry = ttk.Entry(root)
process_name_entry.pack(pady=5)

find_button = ttk.Button(root, text="Find Process", command=find_and_display_process)
find_button.pack(pady=10)

result_label = ttk.Label(root, text="")
result_label.pack()

# Start the GUI event loop
root.mainloop()
