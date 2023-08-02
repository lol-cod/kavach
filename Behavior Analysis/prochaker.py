import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)  # Full access rights to the process

def get_process_handle(process_id):
    return kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)

def read_memory(process_handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    if kernel32.ReadProcessMemory(process_handle, address, buffer, size, ctypes.byref(bytes_read)):
        return buffer.raw[:bytes_read.value]
    else:
        raise ctypes.WinError(ctypes.get_last_error())

def main():
    process_id = 8772  # Replace with the target process ID (e.g., Notepad)
    memory_address = 0x00400000  # Replace with the specific memory address to read
    data_size = 16

    try:
        process_handle = get_process_handle(process_id)
        data = read_memory(process_handle, memory_address, data_size)

        print(f"Data at memory address 0x{memory_address:08X} in process with PID {process_id}:")
        for byte in data:
            print(f"{byte:02X}", end=" ")

        kernel32.CloseHandle(process_handle)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
