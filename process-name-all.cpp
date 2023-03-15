#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

int main()
{
    // Create a snapshot of all running processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Error: Unable to create snapshot of running processes." << std::endl;
        return 1;
    }

    // Initialize the PROCESSENTRY32 structure
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process in the snapshot
    if (!Process32First(snapshot, &processEntry)) {
        std::cout << "Error: Unable to get first process." << std::endl;
        CloseHandle(snapshot);
        return 1;
    }

    // Iterate through all running processes
    do {
        std::cout << processEntry.szExeFile << std::endl;
    } while (Process32Next(snapshot, &processEntry));

    // Clean up the snapshot handle
    CloseHandle(snapshot);

    return 0;
}
