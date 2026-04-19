rule DataExfiltration_DNS_HTTP
{
    meta:
        author      = "Farhad"
        description = "Detects data staging and exfiltration via DNS tunnelling or HTTP"
        category    = "Exfiltration"
        mitre       = "T1048"
        date        = "2026-04-19"
        version     = "1.0"

    strings:
        // DNS exfiltration
        $d1 = "DnsQuery"           ascii wide
        $d2 = "DnsQueryA"          ascii wide
        $d3 = "dnsapi"             ascii wide nocase

        // HTTP exfiltration
        $h1 = "WinHttpOpen"        ascii wide
        $h2 = "WinHttpSendRequest" ascii wide
        $h3 = "InternetOpenUrl"    ascii wide
        $h4 = "HttpSendRequest"    ascii wide

        // Data staging patterns
        $s1 = "CompressEx"         ascii wide
        $s2 = "ZipFile"            ascii wide nocase
        $s3 = "base64"             ascii wide nocase
        $s4 = "ToBase64String"     ascii wide

        // Suspicious target patterns
        $t1 = "pastebin"           ascii wide nocase
        $t2 = "raw.githubusercontent" ascii wide nocase
        $t3 = "ngrok"              ascii wide nocase
        $t4 = "requestbin"         ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (
            1 of ($t*)
            or (2 of ($d*) and 1 of ($s*))
            or (2 of ($h*) and 1 of ($s*))
        )
}
