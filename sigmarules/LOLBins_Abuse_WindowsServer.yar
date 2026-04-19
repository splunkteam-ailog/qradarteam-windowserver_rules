rule LOLBins_Abuse_WindowsServer
{
    meta:
        author      = "Farhad"
        description = "Detects abuse of built-in Windows binaries for malicious execution"
        category    = "Defense Evasion"
        mitre       = "T1218"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // LOLBins commonly abused on servers
        $l1 = "certutil.exe"   ascii wide nocase
        $l2 = "mshta.exe"      ascii wide nocase
        $l3 = "regsvr32.exe"   ascii wide nocase
        $l4 = "rundll32.exe"   ascii wide nocase
        $l5 = "wmic.exe"       ascii wide nocase
        $l6 = "bitsadmin.exe"  ascii wide nocase
        $l7 = "cmstp.exe"      ascii wide nocase
        $l8 = "msiexec.exe"    ascii wide nocase

        // Suspicious arguments
        $a1 = "-urlcache"      ascii wide nocase  // certutil download
        $a2 = "-decode"        ascii wide nocase  // certutil decode
        $a3 = "scrobj.dll"     ascii wide nocase  // regsvr32 scriptlet
        $a4 = "/Transfer"      ascii wide nocase  // bitsadmin download
        $a5 = "javascript:"    ascii wide nocase  // mshta inline JS

    condition:
        filesize < 10MB
        and 2 of ($l*)
        and 1 of ($a*)
}
