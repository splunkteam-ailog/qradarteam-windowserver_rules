rule Suspicious_EXE_Generic_Windows
{
    meta:
        author = "Farhad"
        description = "Detects suspicious Windows executable patterns"
        date = "2026-04-19"
        version = "1.0"

    strings:
        $mz = { 4D 5A }
        $s1 = "VirtualAlloc" ascii wide
        $s2 = "WriteProcessMemory" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
        $s4 = "GetProcAddress" ascii wide
        $s5 = "LoadLibraryA" ascii wide
        $s6 = "powershell" ascii wide
        $s7 = "cmd.exe" ascii wide
        $s8 = "http://" ascii wide
        $s9 = "https://" ascii wide

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
