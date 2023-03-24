#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>

int main(int argc, char* argv[])
{
    // Check if the dump file name is provided as an argument
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <memory_dump_file>" << std::endl;
        return 1;
    }

    // Initialize the symbol handler
    SymInitialize(GetCurrentProcess(), nullptr, TRUE);

    // Open the memory dump file
    HANDLE dumpFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (dumpFile == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open the dump file" << std::endl;
        return 1;
    }

    // Load the memory dump file into the process
    HANDLE process = GetCurrentProcess();
    HANDLE dump = CreateFileMapping(dumpFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    PVOID dumpView = MapViewOfFile(dump, FILE_MAP_READ, 0, 0, 0);

    // Initialize the context for the dump analysis
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_ALL;

    // Analyze the dump
    BOOL result = MiniDumpReadDumpStream(dumpView, MemoryDump, nullptr, nullptr, &context, nullptr, nullptr);
    if (!result) {
        std::cout << "Failed to read the dump" << std::endl;
        return 1;
    }

    // Print the context information
    std::cout << "Context information:" << std::endl;
    std::cout << "  Rax = " << std::hex << context.Rax << std::endl;
    std::cout << "  Rbx = " << std::hex << context.Rbx << std::endl;
    std::cout << "  Rcx = " << std::hex << context.Rcx << std::endl;
    std::cout << "  Rdx = " << std::hex << context.Rdx << std::endl;
    std::cout << "  Rsi = " << std::hex << context.Rsi << std::endl;
    std::cout << "  Rdi = " << std::hex << context.Rdi << std::endl;
    std::cout << "  Rbp = " << std::hex << context.Rbp << std::endl;
    std::cout << "  Rsp = " << std::hex << context.Rsp << std::endl;
    std::cout << "  Rip = " << std::hex << context.Rip << std::endl;
    std::cout << "  R8  = " << std::hex << context.R8 << std::endl;
    std::cout << "  R9  = " << std::hex << context.R9 << std::endl;
    std::cout << "  R10 = " << std::hex << context.R10 << std::endl;
    std::cout << "  R11 = " << std::hex << context.R11 << std::endl;
    std::cout << "  R12 = " << std::hex << context.R12 << std::endl;
    std::cout << "  R13 = " << std::hex << context.R13 << std::endl;
    std::cout << "  R14 = " << std::hex << context
