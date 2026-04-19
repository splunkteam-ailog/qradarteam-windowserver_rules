rule Suspicious_EXE_Generic_Windows
{
    meta:
        author      = "Farhad"
        description = "Detects suspicious Windows executable patterns"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Process injection API
        $s1 = "VirtualAlloc"        ascii wide
        $s2 = "WriteProcessMemory"  ascii wide
        $s3 = "CreateRemoteThread"  ascii wide

        // Dynamic loading
        $s4 = "GetProcAddress"      ascii wide
        $s5 = "LoadLibraryA"        ascii wide

        // Shell execution
        $s6 = "powershell"          ascii wide
        $s7 = "cmd.exe"             ascii wide

        // Network indicators
        $s8 = "http://"             ascii wide
        $s9 = "https://"            ascii wide

    condition:
        // Проверка MZ-сигнатуры (uint16 предпочтительнее строки — не добавляет строку в поиск)
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and 3 of ($s*)
}
