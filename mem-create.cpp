#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>

int main()
{
    // Specify the process ID to dump
    DWORD processId = 1234; // Replace with actual process ID

    // Open the process with PROCESS_VM_READ and PROCESS_QUERY_INFORMATION access
    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (processHandle == NULL) {
        std::cout << "Error: Unable to open process." << std::endl;
        return 1;
    }

    // Create a handle to the dump file
    HANDLE dumpFileHandle = CreateFile(L"memory.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dumpFileHandle == INVALID_HANDLE_VALUE) {
        std::cout << "Error: Unable to create dump file." << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    // Write the memory dump to the file
    BOOL success = MiniDumpWriteDump(processHandle, processId, dumpFileHandle, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!success) {
        std::cout << "Error: Unable to write memory dump to file." << std::endl;
        CloseHandle(processHandle);
        CloseHandle(dumpFileHandle);
        return 1;
    }

    // Close the handles
    CloseHandle(processHandle);
    CloseHandle(dumpFileHandle);

    return 0;
}
