{
    meta:
        author      = "Farhad"
        description = "Detects malware establishing persistence via Windows Registry Run keys"
        category    = "Persistence"
        mitre       = "T1547.001"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Registry API
        $r1 = "RegSetValueEx"     ascii wide
        $r2 = "RegOpenKeyEx"      ascii wide
        $r3 = "RegCreateKeyEx"    ascii wide

        // Common persistence key paths
        $k1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"        ascii wide nocase
        $k2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"    ascii wide nocase
        $k3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $k4 = "SYSTEM\\CurrentControlSet\\Services"                      ascii wide nocase
        $k5 = "CurrentVersion\\Explorer\\Shell Folders"                  ascii wide nocase

        // Suspicious payloads in value names
        $v1 = "powershell"   ascii wide nocase
        $v2 = "wscript"      ascii wide nocase
        $v3 = "mshta"        ascii wide nocase
        $v4 = "regsvr32"     ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and 2 of ($r*)
        and (1 of ($k*) or 1 of ($v*))
}
