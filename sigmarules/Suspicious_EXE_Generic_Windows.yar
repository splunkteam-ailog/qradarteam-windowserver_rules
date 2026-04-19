rule Suspicious_EXE_Generic_Windows
{
    meta:
        author = "OpenAI"
        description = "Detects suspicious Windows executable patterns often seen in loaders, droppers, and injectors"
        date = "2026-04-19"
        version = "1.0"

    strings:
        $mz = { 4D 5A }
        $s1 = "VirtualAlloc" ascii wide
        $s2 = "WriteProcessMemory" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
        $s4 = "NtUnmapViewOfSection" ascii wide
        $s5 = "LoadLibraryA" ascii wide
        $s6 = "LoadLibraryW" ascii wide
        $s7 = "GetProcAddress" ascii wide
        $s8 = "cmd.exe" ascii wide
        $s9 = "powershell" ascii wide
        $s10 = "FromBase64String" ascii wide
        $s11 = "http://" ascii wide
        $s12 = "https://" ascii wide
        $s13 = ".exe" ascii wide
        $s14 = "AppData" ascii wide
        $s15 = "Temp" ascii wide
        $s16 = "Startup" ascii wide
        $s17 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $s18 = "IsDebuggerPresent" ascii wide
        $s19 = "Sleep" ascii wide
        $s20 = "WSAStartup" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        4 of ($s*) and
        1 of ($s1,$s2,$s3,$s4,$s5,$s6,$s7)
}
