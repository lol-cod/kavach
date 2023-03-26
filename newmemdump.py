import win32api
import win32con
import win32process

def create_memory_dump(pid, file_path):
    handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
    win32process.DumpProcess(handle, file_path, 1) # 1 = MiniDumpWithFullMemory
    
pid = 1234
file_path = "C:\\path\\to\\dumpfile.dmp"
create_memory_dump(pid, file_path)
