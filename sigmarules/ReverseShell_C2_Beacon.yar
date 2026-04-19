rule ReverseShell_C2_Beacon
{
    meta:
        author      = "Farhad"
        description = "Detects reverse shell and C2 beacon patterns"
        category    = "Command and Control"
        mitre       = "T1071.001"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Socket / networking
        $n1 = "WSAStartup"         ascii wide
        $n2 = "WSAConnect"         ascii wide
        $n3 = "socket"             ascii wide
        $n4 = "connect"            ascii wide
        $n5 = "recv"               ascii wide
        $n6 = "send"               ascii wide

        // Shell redirection (stdin/stdout → socket)
        $sh1 = "cmd.exe"           ascii wide nocase
        $sh2 = "STARTUPINFO"       ascii wide
        $sh3 = "CreateProcess"     ascii wide
        $sh4 = "GetStdHandle"      ascii wide

        // Cobalt Strike / Meterpreter patterns
        $cs1 = "ReflectiveLoader"  ascii wide
        $cs2 = "beacon"            ascii wide nocase
        $cs3 = "%s as %s\\%s"      ascii wide   // Cobalt Strike named pipe format
        $cs4 = "METERPRETER"       ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (
            1 of ($cs*)
            or (3 of ($n*) and 2 of ($sh*))
        )
}
