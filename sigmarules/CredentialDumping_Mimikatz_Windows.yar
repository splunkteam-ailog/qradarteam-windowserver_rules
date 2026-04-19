rule CredentialDumping_Mimikatz_Windows
{
    meta:
        author      = "Farhad"
        description = "Detects Mimikatz and credential dumping tools"
        category    = "Credential Access"
        mitre       = "T1003"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Mimikatz-specific strings
        $m1 = "mimikatz"           ascii wide nocase
        $m2 = "sekurlsa"           ascii wide nocase
        $m3 = "kerberos::list"     ascii wide nocase
        $m4 = "lsadump::sam"       ascii wide nocase
        $m5 = "privilege::debug"   ascii wide nocase
        $m6 = "mimilib"            ascii wide nocase

        // LSASS-related API calls
        $a1 = "LsaEnumerateLogonSessions"  ascii wide
        $a2 = "MiniDumpWriteDump"          ascii wide
        $a3 = "OpenProcess"                ascii wide
        $a4 = "ReadProcessMemory"          ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (
            2 of ($m*)
            or 3 of ($a*)
            or (1 of ($m*) and 2 of ($a*))
        )
}
