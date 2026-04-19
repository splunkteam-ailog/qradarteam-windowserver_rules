rule LateralMovement_PsExec_SMB
{
    meta:
        author      = "Farhad"
        description = "Detects PsExec-style lateral movement and SMB-based execution"
        category    = "Lateral Movement"
        mitre       = "T1021.002"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // PsExec markers
        $p1 = "psexesvc"          ascii wide nocase
        $p2 = "PSEXESVC"          ascii wide
        $p3 = "PsExec"            ascii wide nocase

        // SMB service manipulation
        $s1 = "\\\\%s\\IPC$"      ascii wide
        $s2 = "\\\\%s\\ADMIN$"    ascii wide
        $s3 = "\\\\%s\\C$"        ascii wide
        $s4 = "OpenSCManager"     ascii wide
        $s5 = "CreateService"     ascii wide
        $s6 = "StartService"      ascii wide
        $s7 = "NetUseAdd"         ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (
            1 of ($p*)
            or 4 of ($s*)
            or (2 of ($s*) and 1 of ($p*))
        )
}
