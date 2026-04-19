rule PrivilegeEscalation_Generic_Windows
{
    meta:
        author      = "Farhad"
        description = "Detects token manipulation and privilege escalation techniques"
        category    = "Privilege Escalation"
        mitre       = "T1134"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Token manipulation API
        $t1 = "AdjustTokenPrivileges"   ascii wide
        $t2 = "ImpersonateLoggedOnUser" ascii wide
        $t3 = "DuplicateTokenEx"        ascii wide
        $t4 = "OpenProcessToken"        ascii wide
        $t5 = "LookupPrivilegeValue"    ascii wide
        $t6 = "SetThreadToken"          ascii wide

        // UAC bypass
        $u1 = "fodhelper.exe"           ascii wide nocase
        $u2 = "eventvwr.exe"            ascii wide nocase
        $u3 = "ComputerDefaults.exe"    ascii wide nocase

        // Named privilege constants
        $p1 = "SeDebugPrivilege"        ascii wide
        $p2 = "SeTcbPrivilege"          ascii wide
        $p3 = "SeImpersonatePrivilege"  ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (
            3 of ($t*)
            or (1 of ($u*) and 1 of ($p*))
            or (2 of ($t*) and 1 of ($p*))
        )
}
