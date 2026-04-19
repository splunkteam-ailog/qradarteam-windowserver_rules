rule Ransomware_Generic_Windows
{
    meta:
        author      = "Farhad"
        description = "Detects generic ransomware behaviour patterns on Windows Server"
        category    = "Impact"
        mitre       = "T1486"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Encryption API
        $e1 = "CryptEncrypt"        ascii wide
        $e2 = "CryptGenKey"         ascii wide
        $e3 = "CryptAcquireContext" ascii wide
        $e4 = "BCryptEncrypt"       ascii wide

        // Ransom note keywords
        $r1 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $r2 = "bitcoin"                  ascii wide nocase
        $r3 = "decrypt"                  ascii wide nocase
        $r4 = "ransom"                   ascii wide nocase
        $r5 = ".onion"                   ascii wide nocase

        // Shadow copy deletion (critical for servers)
        $v1 = "vssadmin delete shadows"  ascii wide nocase
        $v2 = "wmic shadowcopy delete"   ascii wide nocase
        $v3 = "bcdedit /set recoveryenabled no" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 15MB
        and (
            2 of ($e*)
            or 2 of ($r*)
            or 1 of ($v*)
            or (1 of ($e*) and 1 of ($r*))
        )
}
