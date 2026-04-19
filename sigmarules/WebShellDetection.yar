rule Webshell_Generic_WindowsServer
{
    meta:
        author      = "Farhad"
        description = "Detects common web shells deployed on Windows IIS servers"
        category    = "Persistence"
        mitre       = "T1505.003"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // Command execution via web
        $w1 = "cmd.exe /c"             ascii wide nocase
        $w2 = "eval(Request"           ascii nocase
        $w3 = "eval(base64_decode"     ascii nocase
        $w4 = "System.Diagnostics.Process" ascii wide
        $w5 = "ProcessStartInfo"       ascii wide

        // Common web shell keywords
        $w6 = "shell_exec"             ascii nocase
        $w7 = "passthru"               ascii nocase
        $w8 = "<%@ Page Language"      ascii nocase

        // Obfuscation patterns
        $o1 = "FromBase64String"       ascii wide
        $o2 = "Convert.FromBase64"     ascii wide
        $o3 = "GZipStream"             ascii wide

    condition:
        filesize < 500KB
        and (
            (2 of ($w*) and 1 of ($o*))
            or 3 of ($w*)
        )
}
