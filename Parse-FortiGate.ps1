#Requires -Version 5.1
<#
.SYNOPSIS
    Parse a FortiGate configuration backup for CIS IG1 compliance assessment.

.DESCRIPTION
    Reads a FortiGate .conf configuration export and produces structured JSON
    output covering all CIS IG1 safeguards measurable from the firewall config.

    Designed to complement Collect.ps1 -- run both, then feed all output folders
    to Analysis-Prompt.txt for a unified endpoint + network CIS IG1 report.

    CIS controls covered:
      CIS 6.4/6.5  -- VPN and admin MFA configuration
      CIS 8.3/8.7  -- Log retention and centralized logging (syslog/FortiAnalyzer)
      CIS 9.2/9.3  -- DNS filtering and URL/web category filtering
      CIS 10.1/10.3 -- AV and IPS profile existence and deployment
      CIS 12.1     -- Firmware version / EOL status
      CIS 12.2     -- Network segmentation (VLANs, zones)
      CIS 12.3     -- Secure management access (trusted hosts, default account, telnet)
      CIS 12.5     -- Centralized authentication (LDAP/RADIUS/AD)

    Does NOT require network access -- works entirely from a config file export.
    Export from FortiGate:
      GUI: System > Config > Backup > Download
      CLI: execute backup config tftp <filename> <tftp-server>
           or paste "show full-configuration" output to a .conf file

.PARAMETER ConfigFile
    Path to the FortiGate configuration file (.conf or .txt).
    If omitted, the script looks for any *.conf file in the current directory.

.PARAMETER OutputRoot
    Directory where output folder is created.
    Default: same directory as ConfigFile.

.PARAMETER Help
    Show this help and exit.

.OUTPUTS
    FortiGate_<name>_<timestamp>\
      01_fg_device_info.json         Device model, firmware, hostname
      02_fg_admin_accounts.json      Admin users, profiles, trusted hosts, MFA
      02_fg_interface_access.json    Per-interface management access methods
      02_fg_interface_access_FLAGGED.json  Interfaces with HTTP/telnet (if any)
      03_fg_vpn_ssl.json             SSL VPN configuration summary
      03_fg_vpn_ipsec.json           IPsec tunnel inventory
      04_fg_auth_servers.json        LDAP, RADIUS, TACACS+ servers
      05_fg_firewall_policies.json   All firewall policies
      05_fg_policies_FLAGGED.json    Permissive rules (any/any, service ALL) if any
      06_fg_webfilter_profiles.json  Web filter profiles
      06_fg_dnsfilter_profiles.json  DNS filter profiles
      07_fg_av_profiles.json         Antivirus profiles
      07_fg_ips_sensors.json         IPS sensor inventory
      08_fg_logging.json             Disk/FortiAnalyzer/syslog settings
      09_fg_network_segments.json    VLANs, zones, interface summary
      10_fg_cis_ig1.json             CIS IG1 compliance results (machine-readable)
      10_fg_quick_indicators.json    Risk flags summary (start here)
      parse_log.txt                  Run log

.EXAMPLE
    .\Parse-FortiGate.ps1 -ConfigFile "C:\Audits\FW01.conf"

.EXAMPLE
    .\Parse-FortiGate.ps1 -ConfigFile "D:\FW01.conf" -OutputRoot "E:\Audits"
#>

param(
    [string]$ConfigFile = "",
    [string]$OutputRoot = "",
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────────────────────────────────────
# HELP
# ─────────────────────────────────────────────────────────────────────────────

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

$script:sectionStart = $null

function Start-Section {
    param([string]$Name)
    $script:sectionStart = Get-Date
    Write-Host ""
    Write-Host "  [$Name]" -ForegroundColor White
}

function End-Section {
    $elapsed = [int]((Get-Date) - $script:sectionStart).TotalSeconds
    Write-Host "    done (${elapsed}s)" -ForegroundColor DarkGray
}

function Write-Flag {
    param([string]$Msg)
    Write-Host "    FLAG: $Msg" -ForegroundColor Yellow
    Add-Content -Path $script:logFile -Value "FLAG: $Msg"
}

function Write-Warn {
    param([string]$Msg)
    Write-Host "    WARN: $Msg" -ForegroundColor DarkYellow
}

function Save-Json {
    param([string]$FilePath, [object]$Data)
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8NoBOM
    Write-Host "    -> $(Split-Path $FilePath -Leaf)" -ForegroundColor DarkGray
}

# Extract all lines within a named top-level config section.
# Handles nested config/end blocks by tracking depth.
function Get-FGTSection {
    param(
        [string[]]$Lines,
        [string]$SectionName    # e.g. "system global", "firewall policy"
    )

    $pattern = "^\s*config\s+$([regex]::Escape($SectionName))\s*$"
    $result  = [System.Collections.Generic.List[string]]::new()
    $depth   = 0
    $in      = $false

    foreach ($line in $Lines) {
        $t = $line.Trim()

        if (-not $in) {
            if ($t -match $pattern) { $in = $true; $depth = 1 }
            continue
        }

        if ($t -match '^config\s') { $depth++ }

        if ($t -eq 'end') {
            $depth--
            if ($depth -eq 0) { $in = $false; break }
        }

        $result.Add($line)
    }

    return , $result.ToArray()
}

# Parse edit/next entries from section lines into a list of hashtables.
# Each hashtable has _name plus all set key=value pairs at the top level of
# the edit block (does not recurse into nested config blocks inside an entry).
function Parse-FGTEntries {
    param([string[]]$SectionLines)

    $entries = [System.Collections.Generic.List[hashtable]]::new()
    $current = $null
    $depth   = 0

    foreach ($line in $SectionLines) {
        $t = $line.Trim()

        if ($t -match '^edit\s+(.+)$') {
            if ($depth -eq 0) {
                $name    = $matches[1].Trim('"')
                $current = @{ _name = $name }
            }
            $depth++
        }
        elseif ($t -eq 'next') {
            $depth--
            if ($depth -eq 0 -and $current) {
                $entries.Add($current)
                $current = $null
            }
        }
        elseif ($t -match '^config\s') {
            $depth++
        }
        elseif ($t -eq 'end' -and $depth -ge 2) {
            $depth--
        }
        elseif ($t -match '^set\s+(\S+)\s*(.*)$' -and $depth -eq 1 -and $current) {
            $key          = $matches[1]
            $val          = $matches[2].Trim('"')
            $current[$key] = $val
        }
    }

    return , $entries.ToArray()
}

# Parse top-level set key/value pairs from section lines (no edit/next context).
function Parse-FGTSettings {
    param([string[]]$SectionLines)

    $settings = [ordered]@{}
    $depth    = 0

    foreach ($line in $SectionLines) {
        $t = $line.Trim()

        if ($t -match '^config\s') { $depth++; continue }
        if ($t -eq 'end')          { if ($depth -gt 0) { $depth-- }; continue }

        if ($depth -eq 0 -and $t -match '^set\s+(\S+)\s*(.*)$') {
            $key            = $matches[1]
            $val            = $matches[2].Trim('"')
            $settings[$key] = $val
        }
    }

    return $settings
}

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATE INPUT
# ─────────────────────────────────────────────────────────────────────────────

if (-not $ConfigFile) {
    $found = Get-ChildItem -Path (Get-Location) -Filter "*.conf" -File |
             Select-Object -First 1
    if ($found) {
        $ConfigFile = $found.FullName
        Write-Host "  Auto-detected config: $ConfigFile" -ForegroundColor DarkGray
    } else {
        Write-Host "ERROR: No .conf file specified and none found in current directory." -ForegroundColor Red
        Write-Host "Usage: .\Parse-FortiGate.ps1 -ConfigFile <path-to-config.conf>" -ForegroundColor Yellow
        exit 1
    }
}

if (-not (Test-Path $ConfigFile)) {
    Write-Host "ERROR: Config file not found: $ConfigFile" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# SETUP OUTPUT DIRECTORY
# ─────────────────────────────────────────────────────────────────────────────

$timestamp      = Get-Date -Format "yyyyMMdd_HHmmss"
$configBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ConfigFile)

if (-not $OutputRoot) {
    $OutputRoot = Split-Path $ConfigFile -Parent
}

$OutputPath = Join-Path $OutputRoot "FortiGate_${configBaseName}_$timestamp"
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$script:logFile = Join-Path $OutputPath "parse_log.txt"
"Parse-FortiGate.ps1 started at $(Get-Date)" | Out-File $script:logFile -Encoding utf8NoBOM
"Config: $ConfigFile"                          | Add-Content $script:logFile

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Parse-FortiGate.ps1" -ForegroundColor White
Write-Host "  Config : $ConfigFile" -ForegroundColor Gray
Write-Host "  Output : $OutputPath" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# READ CONFIG FILE
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  Reading config..." -ForegroundColor DarkGray
$configLines = Get-Content -Path $ConfigFile -Encoding UTF8 -ErrorAction Stop
Write-Host "  $($configLines.Count) lines loaded" -ForegroundColor DarkGray

# ─────────────────────────────────────────────────────────────────────────────
# CIS IG1 TRACKING HASHTABLES
# ─────────────────────────────────────────────────────────────────────────────

$cisIG1 = [ordered]@{
    # CIS 6.4/6.5
    VPN_MFA_Enabled           = $null   # SSL VPN requires MFA (cert, RADIUS, FortiToken)
    Admin_MFA_Enabled         = $null   # Admin accounts have 2FA
    # CIS 8.3/8.7
    LogRetentionConfigured    = $null   # Disk logging enabled
    CentralizedLogging        = $null   # FortiAnalyzer or syslog configured
    FortiAnalyzerConfigured   = $null
    SyslogConfigured          = $null
    # CIS 9.2/9.3
    DNSFilterProfileExists    = $null
    DNSFilterAppliedInPolicy  = $null
    WebFilterProfileExists    = $null
    WebFilterAppliedInPolicy  = $null
    # CIS 10.1/10.3
    AVProfileExists           = $null
    AVAppliedInPolicy         = $null
    IPSProfileExists          = $null
    IPSAppliedInPolicy        = $null
    # CIS 12.1
    FirmwareVersion           = $null
    FirmwarePotentiallyEOL    = $null   # FortiOS 6.x is EOL
    # CIS 12.3
    DefaultAdminAccountExists = $null   # 'admin' account not renamed
    AdminTrustedHostsSet      = $null   # All admins have trusted host restrictions
    AdminHTTPSOnly            = $null   # No plain HTTP management port
    TelnetDisabled            = $null
    # CIS 12.5
    CentralizedAuthConfigured = $null   # LDAP/RADIUS/TACACS+
    LDAPConfigured            = $null
    RADIUSConfigured          = $null
}

$indicators = [ordered]@{
    DefaultAdminAccount       = $false
    AdminNoTrustedHosts       = $false
    TelnetEnabled             = $false
    AnyAnyFirewallRule        = $false
    NoWebFilter               = $false
    NoDNSFilter               = $false
    NoAV                      = $false
    NoIPS                     = $false
    NoMFA_VPN                 = $false
    NoMFA_Admin               = $false
    NoCentralizedLogging      = $false
    FirmwarePossiblyEOL       = $false
    HTTPManagementEnabled     = $false
    InsecureLDAP              = $false
    PermissivePoliciesExist   = $false
    FlatNetwork               = $false
}

# Pre-parse shared sections used by multiple checks
$interfaceLines   = Get-FGTSection -Lines $configLines -SectionName "system interface"
$interfaceEntries = Parse-FGTEntries -SectionLines $interfaceLines
$globalLines      = Get-FGTSection -Lines $configLines -SectionName "system global"
$globalSettings   = Parse-FGTSettings -SectionLines $globalLines

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 01: DEVICE INFO (CIS 12.1)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "01: Device Info (CIS 12.1)"

$deviceInfo = [ordered]@{
    ConfigFile      = $ConfigFile
    ParsedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Model           = "unknown"
    FirmwareVersion = "unknown"
    BuildNumber     = "unknown"
    Serial          = "unknown"
    Hostname        = if ($globalSettings['hostname'])     { $globalSettings['hostname'] }     else { "unknown" }
    Timezone        = if ($globalSettings['timezone'])     { $globalSettings['timezone'] }     else { "unknown" }
    AdminHTTPSPort  = if ($globalSettings['admin-sport'])  { $globalSettings['admin-sport'] }  else { "443" }
    AdminHTTPPort   = if ($globalSettings['admin-port'])   { $globalSettings['admin-port'] }   else { "disabled" }
    AdminSSHPort    = if ($globalSettings['admin-ssh-port']) { $globalSettings['admin-ssh-port'] } else { "22" }
    Language        = if ($globalSettings['language'])     { $globalSettings['language'] }     else { "english" }
}

# Header format: #config-version=FGT60F-7.2.5-FW-build1517-221128:opmode=0:vdom=0:user=admin
$headerLine = $configLines | Where-Object { $_ -match '#config-version=' } | Select-Object -First 1
if ($headerLine) {
    if ($headerLine -match '#config-version=([^:]+)') {
        $v = $matches[1]
        if ($v -match '^([A-Z0-9]+)-(\d+\.\d+\.\d+)-FW-build(\d+)') {
            $deviceInfo.Model           = $matches[1]
            $deviceInfo.FirmwareVersion = $matches[2]
            $deviceInfo.BuildNumber     = $matches[3]
        } elseif ($v -match '^([A-Z0-9]+)-(\d+\.\d+\.\d+)') {
            $deviceInfo.Model           = $matches[1]
            $deviceInfo.FirmwareVersion = $matches[2]
        }
    }
    if ($headerLine -match 'serial=([A-Z0-9]+)') { $deviceInfo.Serial = $matches[1] }
}

# Fallback: ## MODEL-VERSION header style
if ($deviceInfo.Model -eq "unknown") {
    $altHeader = $configLines | Where-Object { $_ -match '^##\s+[A-Z]' } | Select-Object -First 1
    if ($altHeader -and $altHeader -match '##\s+([A-Z0-9]+)-(\d+[\.\d]+)') {
        $deviceInfo.Model           = $matches[1]
        $deviceInfo.FirmwareVersion = $matches[2]
    }
}

# EOL check: FortiOS 6.x EOL, 7.0.x approaching EOS
$cisIG1.FirmwareVersion = $deviceInfo.FirmwareVersion
if ($deviceInfo.FirmwareVersion -match '^(\d+)\.') {
    $major = [int]$matches[1]
    $cisIG1.FirmwarePotentiallyEOL = ($major -le 6)
    if ($major -le 6) {
        $indicators.FirmwarePossiblyEOL = $true
        Write-Flag "Firmware $($deviceInfo.FirmwareVersion) is FortiOS 6.x or older -- check support.fortinet.com for EOL status"
    }
}

# HTTP management port check
$cisIG1.AdminHTTPSOnly = ($deviceInfo.AdminHTTPPort -eq "disabled")
if ($deviceInfo.AdminHTTPPort -ne "disabled") {
    $indicators.HTTPManagementEnabled = $true
    Write-Flag "Plain HTTP management port enabled (admin-port=$($deviceInfo.AdminHTTPPort))"
}

Save-Json (Join-Path $OutputPath "01_fg_device_info.json") $deviceInfo
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 02: ADMIN ACCOUNTS + INTERFACE ACCESS (CIS 12.3)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "02: Admin Accounts & Interface Access (CIS 12.3)"

$adminLines   = Get-FGTSection -Lines $configLines -SectionName "system admin"
$adminEntries = Parse-FGTEntries -SectionLines $adminLines

$adminAccounts = foreach ($entry in $adminEntries) {
    # Collect all trusthost keys
    $trustedHosts = $entry.Keys |
        Where-Object { $_ -match '^trusthost\d+$' } |
        ForEach-Object { $entry[$_] } |
        Where-Object { $_ -and $_ -notmatch '^0\.0\.0\.0' }

    [ordered]@{
        Name         = $entry._name
        Profile      = if ($entry['accprofile'])  { $entry['accprofile'] }  else { "unknown" }
        TwoFactor    = if ($entry['two-factor'])  { $entry['two-factor'] }  else { "disable" }
        FortiToken   = if ($entry['fortitoken'])  { $entry['fortitoken'] }  else { "" }
        EmailTo      = if ($entry['email-to'])    { $entry['email-to'] }    else { "" }
        TrustedHosts = @($trustedHosts)
        PasswordSet  = ($null -ne $entry['password'])
    }
}

# CIS checks
$defaultAdmin   = $adminAccounts | Where-Object { $_.Name -eq 'admin' }
$noTrustedHosts = $adminAccounts | Where-Object { $_.TrustedHosts.Count -eq 0 }
$mfaAdmins      = $adminAccounts | Where-Object { $_.TwoFactor -ne 'disable' }

$cisIG1.DefaultAdminAccountExists = [bool]$defaultAdmin
$cisIG1.AdminTrustedHostsSet      = ($noTrustedHosts.Count -eq 0)
$cisIG1.Admin_MFA_Enabled         = (@($mfaAdmins).Count -gt 0)

if ($defaultAdmin)              { $indicators.DefaultAdminAccount = $true; Write-Flag "Default 'admin' account still exists -- should be renamed or disabled" }
if (@($noTrustedHosts).Count -gt 0) { $indicators.AdminNoTrustedHosts = $true; Write-Flag "$(@($noTrustedHosts).Count) admin account(s) have no trusted host restriction (accessible from anywhere)" }
if (@($mfaAdmins).Count -eq 0) { $indicators.NoMFA_Admin = $true; Write-Flag "No admin accounts have MFA (FortiToken/email 2FA) enabled" }

Save-Json (Join-Path $OutputPath "02_fg_admin_accounts.json") $adminAccounts

# Interface access methods
$mgmtAccess = foreach ($entry in $interfaceEntries) {
    if ($entry['allowaccess']) {
        [ordered]@{
            Interface   = $entry._name
            AllowAccess = $entry['allowaccess']
            IP          = if ($entry['ip'])    { $entry['ip'] }    else { "" }
            Alias       = if ($entry['alias']) { $entry['alias'] } else { "" }
            Type        = if ($entry['type'])  { $entry['type'] }  else { "physical" }
        }
    }
}

Save-Json (Join-Path $OutputPath "02_fg_interface_access.json") $mgmtAccess

# Flag telnet or HTTP on any interface
$broadAccess = @($mgmtAccess | Where-Object { $_.AllowAccess -match '\btelnet\b' -or $_.AllowAccess -match '\bhttp\b' })
$cisIG1.TelnetDisabled = -not ($broadAccess | Where-Object { $_.AllowAccess -match '\btelnet\b' })

if ($broadAccess.Count -gt 0) {
    if ($broadAccess | Where-Object { $_.AllowAccess -match '\btelnet\b' }) {
        $indicators.TelnetEnabled = $true
        Write-Flag "Telnet is enabled on one or more interfaces"
    }
    if ($broadAccess | Where-Object { $_.AllowAccess -match '\bhttp\b' }) {
        $indicators.HTTPManagementEnabled = $true
        Write-Flag "Plain HTTP management access enabled on one or more interfaces"
    }
    Save-Json (Join-Path $OutputPath "02_fg_interface_access_FLAGGED.json") $broadAccess
}

End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 03: VPN CONFIGURATION (CIS 6.4)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "03: VPN Configuration (CIS 6.4)"

$vpnSslLines    = Get-FGTSection -Lines $configLines -SectionName "vpn ssl settings"
$vpnSslSettings = Parse-FGTSettings -SectionLines $vpnSslLines

$vpnPortalLines   = Get-FGTSection -Lines $configLines -SectionName "vpn ssl web portal"
$vpnPortalEntries = Parse-FGTEntries -SectionLines $vpnPortalLines

# Authentication rules (contain group references with possible 2FA groups)
$vpnAuthRuleLines   = Get-FGTSection -Lines $configLines -SectionName "vpn ssl web realm"
$vpnAuthRuleEntries = Parse-FGTEntries -SectionLines $vpnAuthRuleLines

# Client cert requirement = a second factor
$vpnRequiresCert = ($vpnSslSettings['reqclientcert'] -eq 'enable')

$vpnSslSummary = [ordered]@{
    SSLVPNConfigured   = ($vpnSslLines.Count -gt 0)
    Port               = if ($vpnSslSettings['port'])         { $vpnSslSettings['port'] }         else { "443" }
    RequireClientCert  = $vpnRequiresCert
    IdleTimeout        = if ($vpnSslSettings['idle-timeout']) { $vpnSslSettings['idle-timeout'] } else { "300" }
    AuthTimeout        = if ($vpnSslSettings['auth-timeout']) { $vpnSslSettings['auth-timeout'] } else { "28800" }
    Portals            = ($vpnPortalEntries | ForEach-Object { $_._name })
    MFANote            = "Verify that authentication-rule groups require a RADIUS/FortiToken 2FA group. Client cert alone satisfies CIS 6.4."
}

# IPsec tunnels
$ipsecPhase1Lines   = Get-FGTSection -Lines $configLines -SectionName "vpn ipsec phase1-interface"
$ipsecPhase1Entries = Parse-FGTEntries -SectionLines $ipsecPhase1Lines

$ipsecSummary = foreach ($entry in $ipsecPhase1Entries) {
    [ordered]@{
        Name          = $entry._name
        Interface     = if ($entry['interface'])  { $entry['interface'] }  else { "" }
        RemoteGW      = if ($entry['remote-gw'])  { $entry['remote-gw'] }  else { "dialup" }
        AuthMethod    = if ($entry['authmethod'])  { $entry['authmethod'] }  else { "psk" }
        IKEVersion    = if ($entry['ike-version']) { $entry['ike-version'] } else { "1" }
        XAuthType     = if ($entry['xauthtype'])   { $entry['xauthtype'] }   else { "disable" }
    }
}

# MFA assessment -- be conservative.
# cert = factor 2; RADIUS configured = likely MFA; neither = flag it.
$cisIG1.VPN_MFA_Enabled = $vpnRequiresCert
if (-not $cisIG1.VPN_MFA_Enabled) { $indicators.NoMFA_VPN = $true }
# Will be updated below if RADIUS is found

Save-Json (Join-Path $OutputPath "03_fg_vpn_ssl.json")   $vpnSslSummary
Save-Json (Join-Path $OutputPath "03_fg_vpn_ipsec.json") $ipsecSummary
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 04: AUTH SERVERS (CIS 12.5)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "04: Auth Servers (CIS 12.5)"

$ldapLines   = Get-FGTSection -Lines $configLines -SectionName "user ldap"
$ldapEntries = Parse-FGTEntries -SectionLines $ldapLines

$radiusLines   = Get-FGTSection -Lines $configLines -SectionName "user radius"
$radiusEntries = Parse-FGTEntries -SectionLines $radiusLines

$tacacsLines   = Get-FGTSection -Lines $configLines -SectionName "user tacacs+"
$tacacsEntries = Parse-FGTEntries -SectionLines $tacacsLines

$authSummary = [ordered]@{
    LDAP = foreach ($e in $ldapEntries) {
        [ordered]@{
            Name       = $e._name
            Server     = if ($e['server'])    { $e['server'] }    else { "" }
            Port       = if ($e['port'])       { $e['port'] }       else { "389" }
            SecureConn = if ($e['secure'])     { $e['secure'] }     else { "disable" }
            BaseDN     = if ($e['dn'])         { $e['dn'] }         else { "" }
            BindType   = if ($e['bind-type'])  { $e['bind-type'] }  else { "anonymous" }
        }
    }
    RADIUS = foreach ($e in $radiusEntries) {
        [ordered]@{
            Name   = $e._name
            Server = if ($e['server'])    { $e['server'] }    else { "" }
            Port   = if ($e['auth-port']) { $e['auth-port'] } else { "1812" }
        }
    }
    TACACS = foreach ($e in $tacacsEntries) {
        [ordered]@{ Name = $e._name; Server = if ($e['server']) { $e['server'] } else { "" } }
    }
}

$cisIG1.LDAPConfigured            = ($ldapEntries.Count -gt 0)
$cisIG1.RADIUSConfigured          = ($radiusEntries.Count -gt 0)
$cisIG1.CentralizedAuthConfigured = ($ldapEntries.Count -gt 0 -or $radiusEntries.Count -gt 0 -or $tacacsEntries.Count -gt 0)

# RADIUS presence strongly implies MFA is possible; clear the flag
if ($cisIG1.RADIUSConfigured) {
    $cisIG1.VPN_MFA_Enabled   = $true
    $cisIG1.Admin_MFA_Enabled = $true
    $indicators.NoMFA_VPN     = $false
    $indicators.NoMFA_Admin   = $false
}

# LDAP without TLS
$insecureLDAP = @($ldapEntries | Where-Object { $_['secure'] -ne 'ldaps' -and $_['secure'] -ne 'starttls' })
if ($insecureLDAP.Count -gt 0) {
    $indicators.InsecureLDAP = $true
    Write-Flag "$($insecureLDAP.Count) LDAP server(s) not using TLS/LDAPS -- credentials sent in cleartext"
}

Save-Json (Join-Path $OutputPath "04_fg_auth_servers.json") $authSummary
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 05: FIREWALL POLICIES
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "05: Firewall Policies"

$policyLines   = Get-FGTSection -Lines $configLines -SectionName "firewall policy"
$policyEntries = Parse-FGTEntries -SectionLines $policyLines

$policies = foreach ($entry in $policyEntries) {
    [ordered]@{
        ID         = $entry._name
        Name       = if ($entry['name'])               { $entry['name'] }               else { "" }
        SrcIntf    = if ($entry['srcintf'])             { $entry['srcintf'] }             else { "" }
        DstIntf    = if ($entry['dstintf'])             { $entry['dstintf'] }             else { "" }
        SrcAddr    = if ($entry['srcaddr'])             { $entry['srcaddr'] }             else { "" }
        DstAddr    = if ($entry['dstaddr'])             { $entry['dstaddr'] }             else { "" }
        Service    = if ($entry['service'])             { $entry['service'] }             else { "" }
        Action     = if ($entry['action'])              { $entry['action'] }              else { "accept" }
        Status     = if ($entry['status'])              { $entry['status'] }              else { "enable" }
        LogTraffic = if ($entry['logtraffic'])          { $entry['logtraffic'] }          else { "disable" }
        AVProfile  = if ($entry['av-profile'])          { $entry['av-profile'] }          else { "" }
        IPSSensor  = if ($entry['ips-sensor'])          { $entry['ips-sensor'] }          else { "" }
        WebFilter  = if ($entry['webfilter-profile'])   { $entry['webfilter-profile'] }   else { "" }
        DNSFilter  = if ($entry['dnsfilter-profile'])   { $entry['dnsfilter-profile'] }   else { "" }
        AppControl = if ($entry['application-list'])    { $entry['application-list'] }    else { "" }
        NAT        = if ($entry['nat'])                 { $entry['nat'] }                 else { "disable" }
        Schedule   = if ($entry['schedule'])            { $entry['schedule'] }            else { "" }
    }
}

$activePolicies = @($policies | Where-Object { $_.Action -eq 'accept' -and $_.Status -ne 'disable' })

# Permissive rule detection: srcaddr=all AND dstaddr=all, or service=ALL with either addr=all
$flaggedPolicies = @($activePolicies | Where-Object {
    ($_.SrcAddr -match '\ball\b' -and $_.DstAddr -match '\ball\b') -or
    ($_.Service -match '\bALL\b'  -and ($_.SrcAddr -match '\ball\b' -or $_.DstAddr -match '\ball\b'))
})

if ($flaggedPolicies.Count -gt 0) {
    $indicators.PermissivePoliciesExist = $true
    $indicators.AnyAnyFirewallRule      = $true
    Write-Flag "$($flaggedPolicies.Count) permissive firewall rule(s) detected (any/any source-dest or ALL service)"
    Save-Json (Join-Path $OutputPath "05_fg_policies_FLAGGED.json") $flaggedPolicies
}

# Profile coverage across active ACCEPT policies
$withAV        = @($activePolicies | Where-Object { $_.AVProfile  -ne '' }).Count
$withIPS       = @($activePolicies | Where-Object { $_.IPSSensor  -ne '' }).Count
$withWebFilter = @($activePolicies | Where-Object { $_.WebFilter  -ne '' }).Count
$withDNSFilter = @($activePolicies | Where-Object { $_.DNSFilter  -ne '' }).Count

Write-Host "    $($activePolicies.Count) active ACCEPT policies -- AV:$withAV  IPS:$withIPS  WebFilter:$withWebFilter  DNSFilter:$withDNSFilter" -ForegroundColor DarkGray

$cisIG1.AVAppliedInPolicy        = ($withAV -gt 0)
$cisIG1.IPSAppliedInPolicy       = ($withIPS -gt 0)
$cisIG1.WebFilterAppliedInPolicy = ($withWebFilter -gt 0)
$cisIG1.DNSFilterAppliedInPolicy = ($withDNSFilter -gt 0)

if ($withAV -eq 0)        { $indicators.NoAV        = $true; Write-Flag "No AV profile applied to any firewall policy" }
if ($withIPS -eq 0)       { $indicators.NoIPS       = $true; Write-Flag "No IPS sensor applied to any firewall policy" }
if ($withWebFilter -eq 0) { $indicators.NoWebFilter = $true; Write-Flag "No web filter profile applied to any firewall policy" }
if ($withDNSFilter -eq 0) { $indicators.NoDNSFilter = $true; Write-Flag "No DNS filter profile applied to any firewall policy" }

Save-Json (Join-Path $OutputPath "05_fg_firewall_policies.json") $policies
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 06: WEB FILTER + DNS FILTER (CIS 9.2/9.3)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "06: Web & DNS Filter Profiles (CIS 9.2/9.3)"

$wfLines    = Get-FGTSection -Lines $configLines -SectionName "webfilter profile"
$wfEntries  = Parse-FGTEntries -SectionLines $wfLines

$dnsLines   = Get-FGTSection -Lines $configLines -SectionName "dnsfilter profile"
$dnsEntries = Parse-FGTEntries -SectionLines $dnsLines

$cisIG1.WebFilterProfileExists = ($wfEntries.Count -gt 0)
$cisIG1.DNSFilterProfileExists = ($dnsEntries.Count -gt 0)

$wfSummary = foreach ($e in $wfEntries) {
    [ordered]@{
        Name           = $e._name
        InspectionMode = if ($e['inspection-mode'])  { $e['inspection-mode'] }  else { "flow" }
        LogAllURL      = if ($e['log-all-url'])       { $e['log-all-url'] }       else { "disable" }
        HTTPSAction    = if ($e['https-replacemsg']) { $e['https-replacemsg'] } else { "" }
    }
}

$dnsSummary = foreach ($e in $dnsEntries) {
    [ordered]@{
        Name           = $e._name
        SafeSearch     = if ($e['safe-search'])       { $e['safe-search'] }       else { "disable" }
        YoutubeRestrict = if ($e['youtube-restrict']) { $e['youtube-restrict'] } else { "none" }
        BlockBotnet    = if ($e['block-botnet'])      { $e['block-botnet'] }      else { "disable" }
    }
}

Save-Json (Join-Path $OutputPath "06_fg_webfilter_profiles.json") $wfSummary
Save-Json (Join-Path $OutputPath "06_fg_dnsfilter_profiles.json") $dnsSummary
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 07: AV + IPS PROFILES (CIS 10.1/10.3)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "07: AV & IPS Profiles (CIS 10.1/10.3)"

$avLines    = Get-FGTSection -Lines $configLines -SectionName "antivirus profile"
$avEntries  = Parse-FGTEntries -SectionLines $avLines

$ipsLines   = Get-FGTSection -Lines $configLines -SectionName "ips sensor"
$ipsEntries = Parse-FGTEntries -SectionLines $ipsLines

$cisIG1.AVProfileExists  = ($avEntries.Count -gt 0)
$cisIG1.IPSProfileExists = ($ipsEntries.Count -gt 0)

$avSummary = foreach ($e in $avEntries) {
    [ordered]@{
        Name        = $e._name
        ScanMode    = if ($e['scan-mode'])       { $e['scan-mode'] }       else { "quick" }
        BotnetDomains = if ($e['botnet-domains']) { $e['botnet-domains'] } else { "disable" }
    }
}

$ipsSummary = foreach ($e in $ipsEntries) {
    [ordered]@{
        Name  = $e._name
        Block = if ($e['block-malicious-url']) { $e['block-malicious-url'] } else { "disable" }
    }
}

Save-Json (Join-Path $OutputPath "07_fg_av_profiles.json")  $avSummary
Save-Json (Join-Path $OutputPath "07_fg_ips_sensors.json")  $ipsSummary
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 08: LOGGING (CIS 8.3/8.7)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "08: Logging (CIS 8.3/8.7)"

$logDiskLines    = Get-FGTSection -Lines $configLines -SectionName "log disk setting"
$logDiskSettings = Parse-FGTSettings -SectionLines $logDiskLines

$logFAZLines    = Get-FGTSection -Lines $configLines -SectionName "log fortianalyzer setting"
$logFAZSettings = Parse-FGTSettings -SectionLines $logFAZLines

$logSyslogLines    = Get-FGTSection -Lines $configLines -SectionName "log syslogd setting"
$logSyslogSettings = Parse-FGTSettings -SectionLines $logSyslogLines

$logSyslog2Lines    = Get-FGTSection -Lines $configLines -SectionName "log syslogd2 setting"
$logSyslog2Settings = Parse-FGTSettings -SectionLines $logSyslog2Lines

$loggingSummary = [ordered]@{
    DiskLogging = [ordered]@{
        Status       = if ($logDiskSettings['status'])          { $logDiskSettings['status'] }          else { "unknown" }
        MaxLogSize   = if ($logDiskSettings['max-log-file-size']) { $logDiskSettings['max-log-file-size'] } else { "unknown" }
        LogQuotaMB   = if ($logDiskSettings['log-quota'])       { $logDiskSettings['log-quota'] }       else { "unknown" }
        Severity     = if ($logDiskSettings['severity'])        { $logDiskSettings['severity'] }        else { "unknown" }
        FullFinalWarn = if ($logDiskSettings['full-final-warning-threshold']) { $logDiskSettings['full-final-warning-threshold'] } else { "unknown" }
    }
    FortiAnalyzer = [ordered]@{
        Status        = if ($logFAZSettings['status'])  { $logFAZSettings['status'] }  else { "disable" }
        Server        = if ($logFAZSettings['server'])  { $logFAZSettings['server'] }  else { "" }
        UploadDay     = if ($logFAZSettings['upload-day']) { $logFAZSettings['upload-day'] } else { "" }
    }
    Syslog = [ordered]@{
        Status = if ($logSyslogSettings['status'])  { $logSyslogSettings['status'] }  else { "disable" }
        Server = if ($logSyslogSettings['server'])  { $logSyslogSettings['server'] }  else { "" }
        Port   = if ($logSyslogSettings['port'])    { $logSyslogSettings['port'] }    else { "514" }
        Format = if ($logSyslogSettings['format'])  { $logSyslogSettings['format'] }  else { "default" }
    }
    Syslog2 = [ordered]@{
        Status = if ($logSyslog2Settings['status']) { $logSyslog2Settings['status'] } else { "disable" }
        Server = if ($logSyslog2Settings['server']) { $logSyslog2Settings['server'] } else { "" }
    }
}

$fazEnabled    = ($logFAZSettings['status'] -eq 'enable')
$syslogEnabled = ($logSyslogSettings['status'] -eq 'enable' -or $logSyslog2Settings['status'] -eq 'enable')

$cisIG1.FortiAnalyzerConfigured  = $fazEnabled
$cisIG1.SyslogConfigured         = $syslogEnabled
$cisIG1.CentralizedLogging       = ($fazEnabled -or $syslogEnabled)
$cisIG1.LogRetentionConfigured   = ($logDiskSettings['status'] -eq 'enable')

if (-not $cisIG1.CentralizedLogging) {
    $indicators.NoCentralizedLogging = $true
    Write-Flag "No centralized logging -- FortiAnalyzer not configured, no syslog server"
}

Save-Json (Join-Path $OutputPath "08_fg_logging.json") $loggingSummary
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 09: NETWORK SEGMENTS (CIS 12.2)
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "09: Network Segments (CIS 12.2)"

$zoneLines   = Get-FGTSection -Lines $configLines -SectionName "system zone"
$zoneEntries = Parse-FGTEntries -SectionLines $zoneLines

$vlanInterfaces = @($interfaceEntries | Where-Object { $_['type'] -eq 'vlan' -or $_['vlanid'] })
$physInterfaces = @($interfaceEntries | Where-Object {
    $_['type'] -eq 'physical' -or
    (-not $_['type'] -and $_._name -match '^(wan\d*|lan\d*|dmz\d*|internal\d*|port\d+|mgmt)$')
})

$segmentSummary = [ordered]@{
    ZoneCount  = $zoneEntries.Count
    Zones      = @($zoneEntries | ForEach-Object { $_._name })
    VLANCount  = $vlanInterfaces.Count
    VLANs      = foreach ($iface in $vlanInterfaces) {
        [ordered]@{
            Name   = $iface._name
            VLANID = if ($iface['vlanid']) { $iface['vlanid'] } else { "" }
            IP     = if ($iface['ip'])     { $iface['ip'] }     else { "" }
            Alias  = if ($iface['alias'])  { $iface['alias'] }  else { "" }
        }
    }
    PhysicalInterfaces = foreach ($iface in $physInterfaces) {
        [ordered]@{
            Name  = $iface._name
            IP    = if ($iface['ip'])    { $iface['ip'] }    else { "" }
            Alias = if ($iface['alias']) { $iface['alias'] } else { "" }
            Role  = if ($iface['role'])  { $iface['role'] }  else { "" }
        }
    }
    SegmentationAssessment = if ($zoneEntries.Count -gt 1 -or $vlanInterfaces.Count -gt 0) {
        "Segmentation detected ($($zoneEntries.Count) zones, $($vlanInterfaces.Count) VLANs)"
    } else {
        "WARNING: No VLANs or multiple zones detected -- possible flat network"
    }
}

if ($zoneEntries.Count -le 1 -and $vlanInterfaces.Count -eq 0) {
    $indicators.FlatNetwork = $true
    Write-Flag "No VLANs or multiple security zones -- network may be flat (all devices on same segment)"
}

Save-Json (Join-Path $OutputPath "09_fg_network_segments.json") $segmentSummary
End-Section

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10: CIS IG1 SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

Start-Section "10: CIS IG1 Summary"

Save-Json (Join-Path $OutputPath "10_fg_cis_ig1.json")          $cisIG1
Save-Json (Join-Path $OutputPath "10_fg_quick_indicators.json") $indicators

"Parse complete at $(Get-Date)" | Add-Content $script:logFile

# Print flag summary
$flagCount = ($indicators.GetEnumerator() | Where-Object { $_.Value -eq $true }).Count
$color     = if ($flagCount -gt 0) { 'Yellow' } else { 'Green' }

Write-Host ""
Write-Host "  ┌─ RISK FLAGS ($flagCount found) ─────────────────────────────────────" -ForegroundColor $color
foreach ($kv in $indicators.GetEnumerator()) {
    if ($kv.Value -eq $true) {
        Write-Host "  │  ⚠  $($kv.Key)" -ForegroundColor Yellow
    }
}
if ($flagCount -eq 0) {
    Write-Host "  │  ✓  No risk flags detected" -ForegroundColor Green
}
Write-Host "  └────────────────────────────────────────────────────────────────" -ForegroundColor $color

End-Section

# ─────────────────────────────────────────────────────────────────────────────
# WRAP-UP
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  COMPLETE" -ForegroundColor White
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor White
Write-Host "    1. Check 10_fg_quick_indicators.json for immediate flags" -ForegroundColor Gray
Write-Host "    2. Review 05_fg_policies_FLAGGED.json if present" -ForegroundColor Gray
Write-Host "    3. Feed this folder + Collect.ps1 evidence folder to the AI" -ForegroundColor Gray
Write-Host "       with Analysis-Prompt.txt for a unified CIS IG1 report" -ForegroundColor Gray
Write-Host "    4. VPN MFA: manually verify authentication-rule groups in the" -ForegroundColor Gray
Write-Host "       config reference RADIUS/FortiToken groups (not just LDAP)" -ForegroundColor Gray
Write-Host "    5. LDAP without TLS: if flagged, check if LDAPS is in use at" -ForegroundColor Gray
Write-Host "       network level even if not reflected in config" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
