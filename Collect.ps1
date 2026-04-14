#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Corporate endpoint forensic evidence collector with CIS IG1 compliance checks.

.DESCRIPTION
    Collects system artifacts, user activity, browser history, network state,
    security events, and CIS IG1 compliance data for authorized internal
    investigations and security audits. Output is a timestamped folder (and
    ZIP archive) containing structured evidence files organized by section.

    LEGAL NOTICE: Only run this on systems you are explicitly authorized to
    investigate. Obtain written authorization from the asset owner before use.

.PARAMETER TargetUser
    The Windows username to focus collection on. Defaults to all local profiles.

.PARAMETER OutputRoot
    Folder where the evidence subfolder will be created.
    Defaults to the directory containing this script (ideal for thumb drive use).
    A timestamped subfolder Evidence_<hostname>_<timestamp> is created inside.

.PARAMETER NetworkScan
    After completing the full local scan, perform a WMI-based triage of all
    other live hosts on the local subnet.

.PARAMETER Subnet
    Three-octet subnet prefix to scan (e.g. "192.168.1"). Only used with
    -NetworkScan. Auto-detected from the local adapter if omitted.

.PARAMETER PingTimeout
    Ping timeout in milliseconds per host during the sweep. Default: 500.

.PARAMETER RemoteCredential
    Alternate PSCredential for WMI queries against remote hosts. Only used
    with -NetworkScan. If omitted, runs as the current user.

.PARAMETER Help
    Show detailed help text and exit.

.EXAMPLE
    .\Collect-Evidence.ps1
    .\Collect-Evidence.ps1 -TargetUser "jsmith"
    .\Collect-Evidence.ps1 -OutputRoot "E:\"
    .\Collect-Evidence.ps1 -NetworkScan -Subnet "10.0.1" -RemoteCredential (Get-Credential)
#>

param(
    [string]$TargetUser  = "",
    [string]$OutputRoot  = "",

    # Network scan options -- only active when -NetworkScan is specified
    [switch]$NetworkScan,
    [string]$Subnet      = "",   # e.g. "192.168.1" -- auto-detected if omitted
    [int]   $PingTimeout = 500,  # ms per host for ping sweep
    [System.Management.Automation.PSCredential]$RemoteCredential = $null,

    [switch]$Help
)

if ($Help) {
    $w = [Math]::Min(([Console]::WindowWidth - 1), 80)
    Write-Host ""
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host "  Collect.ps1  --  Endpoint Forensic Evidence Collector" -ForegroundColor White
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host @"

DESCRIPTION
  Collects forensic artifacts from the local Windows machine for use in
  security audits and internal investigations. Output is a timestamped
  folder (and ZIP archive) containing structured evidence files organized
  by section. All sections are CIS IG1 annotated.

  Run as Administrator for full collection (event logs, Prefetch, registry).
  Obtain written authorization from the asset owner before use.

USAGE
  .\Collect.ps1 [options]

PARAMETERS

  -TargetUser <username>
      Limit user-profile sections (browser history, cloud sync, large files,
      etc.) to a single user. If omitted, all non-system profiles are scanned.
      Example: -TargetUser "jsmith"

  -OutputRoot <path>
      Folder where the evidence subfolder is created. Defaults to the directory
      containing this script (ideal for running from a USB drive). A timestamped
      subfolder Evidence_<HOSTNAME>_<TIMESTAMP> is always created inside.
      Example: -OutputRoot "E:\"

  -NetworkScan
      After completing the full local scan, perform a WMI-based triage of all
      other live hosts on the local subnet. Detects: OS version, RDP state,
      firewall state, AV product, running processes (flagged against known RAT/
      spy/exfil keywords), services, local admin members, and installed remote
      access tools. Results go in a network_scan\ subfolder.
      Requires admin rights on remote machines (current user or -RemoteCredential).

  -Subnet <"A.B.C">
      Three-octet subnet prefix to scan (e.g. "192.168.1" for 192.168.1.0/24).
      Only used with -NetworkScan. Auto-detected from local adapter if omitted.
      Example: -Subnet "10.0.1"

  -PingTimeout <ms>
      Ping timeout in milliseconds per host during the sweep. Default: 500.
      Lower values speed up the sweep on a fast LAN; raise for slow/VPN links.
      Example: -PingTimeout 200

  -RemoteCredential <PSCredential>
      Alternate credentials for WMI queries against remote hosts.
      Only used with -NetworkScan. If omitted, runs as the current user.
      Example: -RemoteCredential (Get-Credential)

  -Help
      Show this help text and exit.

EXAMPLES

  Full local scan, all users, output next to script:
      .\Collect.ps1

  Full local scan focused on one user, output to USB drive:
      .\Collect.ps1 -TargetUser "jsmith" -OutputRoot "E:\"

  Local scan + LAN triage (auto-detect subnet):
      .\Collect.ps1 -NetworkScan

  Local scan + LAN triage with explicit subnet and alternate credentials:
      .\Collect.ps1 -NetworkScan -Subnet "192.168.10" -RemoteCredential (Get-Credential)

  LAN triage only (skip local -- run as a different script call):
      Not supported; local scan always runs. Use network_summary.csv to
      identify machines that warrant a full local collection visit.

OUTPUT FILES (key files -- full list in _collection_log.txt)

  quick_indicators.json         Instant risk flag summary (start here)
  cis_ig1_gaps.json             CIS IG1 compliance gaps (all CIS checks in one file)
  00_metadata.txt               Collection info + public IP for external scanning
  02_logon_events.csv           30 days of logon/logoff/failure events
  03_processes_FLAGGED.txt      Suspicious processes (if any)
  07_dns_cache.txt              Recent DNS lookups (survives browser clear)
  07_defender_status.json       Defender real-time, scan history, signature age
  07_defender_exclusions.json   Defender exclusion paths/procs (attacker abuse)
  07_firewall_profiles.txt      Per-profile firewall state
  07_rdp_settings.json          RDP and NLA configuration
  09b_browser_keyword_FLAGGED   Browser history hits on investigation keywords
  13b_prefetch_FLAGGED.csv      Suspicious executables in Prefetch (if any)
  13c_wmi_persistence.csv       WMI event subscriptions (if any)
  15_cis_dormant_FLAGGED.csv    Dormant enabled accounts (CIS 5.3)
  16_cis_pending_updates_FLAGGED Pending Windows updates (CIS 7.3)
  17_cis_shares_OVERPERMISSIVE  Overpermissive SMB shares (CIS 3.3)
  17_cis_bitlocker_status.csv   Drive encryption status (CIS 3.6)
  18_cis_secure_config.json     SMBv1, LLMNR, NetBIOS status (CIS 4.1)
  18_cis_screen_lock.json       Screen lock / inactivity timeout (CIS 4.3)
  18_cis_audit_log_sizes.json   Event log size and retention (CIS 8.3)
  18_cis_ps_logging.json        PowerShell logging policy (CIS 8.5)
  network_scan\network_summary  Per-host triage results (with -NetworkScan)

  All files marked _FLAGGED, _SUSPICIOUS, or _UNEXPECTED are priority review.
  Evidence folder is automatically zipped at the end of collection.

NOTES
  - Browser history SQLite DBs are copied as-is; open in DB Browser for SQLite
    (https://sqlitebrowser.org) or mine as binary in PowerShell.
  - Win32_Product queries (used for remote software inventory) are slow by
    design -- WMI repair-triggers on access. Expected on remote hosts only.
  - If criminal activity is found, stop and preserve evidence before making
    any additional system changes. Contact legal counsel before proceeding.

"@ -ForegroundColor Gray
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# --- Setup --------------------------------------------------------------------

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME
$investigator = $env:USERNAME

# Default OutputRoot: directory containing this script (thumb drive friendly).
# Fall back to Desktop only if script path can't be determined.
if (-not $OutputRoot) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $OutputRoot = if ($scriptDir) { $scriptDir } else { "$env:USERPROFILE\Desktop" }
}

$OutputPath = Join-Path $OutputRoot "Evidence_${hostname}_$timestamp"

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$script:_scriptStart = Get-Date
$logFile = "$OutputPath\_collection_log.txt"

# Aggregated risk indicators -- populated throughout, written to JSON at end
$script:indicators = [ordered]@{
    Hostname                  = $hostname
    CollectionTime            = (Get-Date).ToString("o")
    Investigator              = $investigator
    RDPEnabled                = $null
    NLARequired               = $null
    FirewallDisabledProfiles  = @()
    DefenderRealtimeEnabled   = $null
    PublicIP                  = $null
    RemoteAccessSoftwareHits  = @()
    SuspiciousProcessCount    = 0
    BrowserKeywordHitCount    = 0
    BrowserKeywordHitDomains  = @()
    ExternalConnectionCount   = 0
    SuspiciousListenerCount   = 0
    VirtualAdaptersFound      = @()
    UsbDeviceCount            = 0
    WebcamUnexpectedAppCount  = 0
    WebcamRelatedProcesses    = @()
}

# CIS IG1 gap tracking -- populated in sections 15-17, written to cis_ig1_gaps.json at end
$script:cisIG1 = [ordered]@{
    DormantAccounts          = @()    # CIS 5.3 - enabled accounts inactive > 90 days
    NeverLoggedInAccounts    = @()    # CIS 5.3 - enabled accounts with no logon history
    PasswordNeverExpires     = @()    # CIS 5.2 - accounts with non-expiring passwords
    PrivilegedAccounts       = @()    # CIS 5.4 - members of Administrators group
    DefaultAdminRenamed      = $null  # CIS 4.7 - built-in Administrator renamed
    DefaultAdminEnabled      = $null  # CIS 4.7 - built-in Administrator enabled
    GuestEnabled             = $null  # CIS 4.7 - Guest account enabled
    DaysSinceLastPatch       = $null  # CIS 7.3 - days since last Windows update installed
    LastPatchKB              = $null  # CIS 7.3 - most recent hotfix ID
    PendingUpdatesCount      = $null  # CIS 7.3 - updates waiting to install
    WindowsBuild             = $null  # CIS 7.4 - OS build string for EOL check
    BrowserVersions          = @{}    # CIS 9.1 - installed browser versions
    NTPSource                = $null  # CIS 8.4 - time sync source
    NTPSynced                = $null  # CIS 8.4 - syncing to external source
    BitLockerStatus          = @()    # CIS 3.6 - per-drive encryption status
    AutorunDisabled          = $null  # CIS 10.3 - autorun disabled for removable media
    OpenShareCount           = 0      # CIS 3.3 - shares with Everyone/Users full/change access
    AllShareNames            = @()    # CIS 12.2 - all configured SMB shares
    SMBv1Enabled             = $null  # CIS 4.1 - SMBv1 protocol enabled (major risk)
    LLMNRDisabled            = $null  # CIS 4.1 - LLMNR disabled (poisoning vector)
    NetBIOSDisabled          = $null  # CIS 4.1 - NetBIOS over TCP disabled
    ScreenLockTimeout        = $null  # CIS 4.3 - screen lock timeout seconds
    ScreenLockEnabled        = $null  # CIS 4.3 - screen lock requires password
    PSScriptBlockLogging     = $null  # CIS 8.5 - PowerShell script block logging
    PSModuleLogging          = $null  # CIS 8.5 - PowerShell module logging
    AuditLogMaxSizes         = @{}    # CIS 8.3 - event log max sizes in MB
    DefenderBehaviorMonitor  = $null  # CIS 10.7 - behavior-based detection enabled
    DefenderExclusions       = @()    # Defender exclusion paths (attacker abuse)
    RemovableDriveScan       = $null  # CIS 10.4 - Defender scans removable media
}

function Log {
    param([string]$msg, [string]$color = "Cyan")
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $entry -ForegroundColor $color
    Add-Content -Path $logFile -Value $entry
}

$script:_secStart = $null
$script:_secName  = $null

function Start-Section {
    param([string]$Name, [string]$Description = "")

    # Auto-close the previous section and report its elapsed time
    if ($script:_secStart) {
        $elapsed = [math]::Round(((Get-Date) - $script:_secStart).TotalSeconds, 1)
        $ts = (Get-Date).ToString("HH:mm:ss")
        Write-Host "[$ts]  [OK]  Done (${elapsed}s)" -ForegroundColor DarkGreen
        Add-Content -Path $logFile -Value "[$ts] END    $script:_secName  (${elapsed}s)"
    }

    $script:_secStart = Get-Date
    $script:_secName  = $Name
    $ts = $script:_secStart.ToString("HH:mm:ss")
    $width = [Math]::Min(([Console]::WindowWidth - 1), 80)

    Write-Host ""
    Write-Host ("-" * $width) -ForegroundColor DarkGray
    Write-Host "[$ts]  " -ForegroundColor DarkGray -NoNewline
    Write-Host ">>  $Name" -ForegroundColor Yellow -NoNewline
    if ($Description) { Write-Host "  --  $Description" -ForegroundColor Gray } else { Write-Host "" }
    Add-Content -Path $logFile -Value "[$ts] START  $Name -- $Description"
}

function End-Section {
    # Call once at the very end to close the final section
    if (-not $script:_secStart) { return }
    $elapsed = [math]::Round(((Get-Date) - $script:_secStart).TotalSeconds, 1)
    $ts = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$ts]  [OK]  Done (${elapsed}s)" -ForegroundColor DarkGreen
    Add-Content -Path $logFile -Value "[$ts] END    $script:_secName  (${elapsed}s)"
    $script:_secStart = $null
    $script:_secName  = $null
}

function Invoke-Skippable {
    <#
    .SYNOPSIS
        Runs a scriptblock as a background job. Press ENTER to skip it.
        Shows a live elapsed-time heartbeat so you know it is still running.
        If the job writes a status string to $StatusFile, it appears in the heartbeat.
        No automatic timeout -- you decide when it has run long enough.
        The scriptblock must write results directly to files via ArgumentList.
    .OUTPUTS
        "done" | "skipped"
    #>
    param(
        [scriptblock]$Action,
        [object[]]   $ArgumentList = @(),
        [string]     $Label        = "operation",
        [string]     $StatusFile   = ""   # optional: job writes status here; shown in heartbeat
    )

    $jobStart  = Get-Date
    $pollCount = 0

    Write-Host ""
    Write-Host "    [>> '$Label'  --  press ENTER to skip]" -ForegroundColor DarkGray

    $job = Start-Job -ScriptBlock $Action -ArgumentList $ArgumentList

    while ($job.State -eq 'Running') {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') {
                Stop-Job $job
                Write-Progress -Activity $Label -Completed
                $elapsed = [int]((Get-Date) - $jobStart).TotalSeconds
                Write-Host "    [SKIPPED '$Label' after ${elapsed}s]" -ForegroundColor DarkYellow
                Add-Content -Path $logFile -Value "    '$Label' skipped by user"
                Remove-Job $job -Force
                if ($StatusFile -and (Test-Path $StatusFile)) { Remove-Item $StatusFile -Force -ErrorAction SilentlyContinue }
                return "skipped"
            }
        }
        Start-Sleep -Milliseconds 200
        $pollCount++
        if ($pollCount % 5 -eq 0) {
            $elapsed = [int]((Get-Date) - $jobStart).TotalSeconds
            $statusNote = ""
            if ($StatusFile -and (Test-Path $StatusFile)) {
                $raw = Get-Content $StatusFile -Raw -ErrorAction SilentlyContinue
                $statusNote = if ($raw) { $raw.Trim() } else { "" }
            }
            $status = if ($statusNote) { "${elapsed}s  |  $statusNote" } else { "${elapsed}s elapsed" }
            Write-Progress -Activity "  >> $Label" -Status $status -SecondsRemaining -1
        }
    }

    Write-Progress -Activity "  >> $Label" -Completed
    $elapsed = [int]((Get-Date) - $jobStart).TotalSeconds
    $finalStatus = ""
    if ($StatusFile -and (Test-Path $StatusFile)) {
        $raw = Get-Content $StatusFile -Raw -ErrorAction SilentlyContinue
        $finalStatus = if ($raw) { "  $($raw.Trim())" } else { "" }
        Remove-Item $StatusFile -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [OK '$Label' done in ${elapsed}s${finalStatus}]" -ForegroundColor DarkGreen
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return "done"
}

function Save {
    param([string]$name, $data)
    $file = "$OutputPath\$name"
    if ($data -is [string]) {
        Set-Content -Path $file -Value $data -Encoding UTF8
    } else {
        $data | Out-File -FilePath $file -Encoding UTF8
    }
    Log "  Saved: $name"
}

function CopyFile {
    param([string]$src, [string]$destName)
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination "$OutputPath\$destName" -Force -ErrorAction SilentlyContinue
        Log "  Copied: $destName"
    } else {
        Log "  Not found: $src" "DarkGray"
    }
}

# Determine which user profiles to examine
if ($TargetUser) {
    $profiles = Get-ChildItem "C:\Users" | Where-Object { $_.Name -ieq $TargetUser }
} else {
    $profiles = Get-ChildItem "C:\Users" | Where-Object { 
        $_.Name -notmatch "^(Public|Default|All Users|desktop\.ini)$" -and $_.PSIsContainer
    }
}

# --- Investigation Metadata ---------------------------------------------------

Start-Section "INVESTIGATION METADATA" "Recording who, what, when, and where for chain of custody"
$meta = @"
Collection Time : $(Get-Date)
Investigator    : $investigator
Target Computer : $hostname
Target User(s)  : $(if ($TargetUser) { $TargetUser } else { "All profiles" })
OS              : $([System.Environment]::OSVersion.VersionString)
PowerShell      : $($PSVersionTable.PSVersion)
Output Path     : $OutputPath
"@
Save "00_metadata.txt" $meta
Write-Host $meta -ForegroundColor Green

# Collect public IP for external exposure assessment / later port scanning
try {
    $publicIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip
    $script:indicators.PublicIP = $publicIP
    Log "  Public IP: $publicIP"
    Add-Content "$OutputPath\00_metadata.txt" "`nPublic IP       : $publicIP"

    # Also try reverse DNS on the public IP
    try {
        $rdns = [System.Net.Dns]::GetHostEntry($publicIP).HostName
        Add-Content "$OutputPath\00_metadata.txt" "Public rDNS     : $rdns"
        Log "  Public rDNS: $rdns"
    } catch {
        Add-Content "$OutputPath\00_metadata.txt" "Public rDNS     : (no PTR record)"
    }
} catch {
    Log "  Could not determine public IP (no internet or api.ipify.org blocked)" "DarkGray"
    $script:indicators.PublicIP = "unknown"
}

# --- System Information -------------------------------------------------------

Start-Section "SYSTEM INFORMATION" "OS version, BIOS, local accounts (CIS 1.1 asset inventory) -- systeminfo may take ~20s (network name resolution)"
Save "01_systeminfo.txt" (systeminfo 2>&1)
Save "01_os_details.txt"  (Get-WmiObject Win32_OperatingSystem | Format-List * | Out-String)
Save "01_bios.txt"        (Get-WmiObject Win32_BIOS | Format-List * | Out-String)
Save "01_local_users.txt" (Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, Description -AutoSize | Out-String)
Save "01_local_groups.txt"(Get-LocalGroup | Format-Table * -AutoSize | Out-String)
Save "01_group_members_admins.txt" (
    & { try { Get-LocalGroupMember -Group "Administrators" | Format-Table * -AutoSize | Out-String }
        catch { "Error: $_" } }
)

# --- Logon & Authentication Events -------------------------------------------

Start-Section "LOGON EVENTS" "Last 30 days of Security log: successes, failures, after-hours logins, privilege use (CIS 8.2 -- validates audit logging is active)"
$since = (Get-Date).AddDays(-30)
$_logonStatusFile = "$env:TEMP\ce_logon_status.tmp"

# Pre-query: check Security log size and give a rough time estimate before blocking
$secLogPath = "$env:SystemRoot\System32\winevt\Logs\Security.evtx"
if (Test-Path $secLogPath) {
    $secLogMB = [math]::Round((Get-Item $secLogPath).Length / 1MB, 0)
    # Empirical: ~1-2 min per 100MB on a typical workstation, longer on domain machines
    $estMinLow  = [math]::Max(1, [math]::Round($secLogMB / 100 * 1, 0))
    $estMinHigh = [math]::Max(2, [math]::Round($secLogMB / 100 * 2, 0))
    $domainNote = if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) { "  (domain-joined -- audit policy likely heavy)" } else { "" }
    Log "  Security log: ${secLogMB}MB -- est. ${estMinLow}-${estMinHigh} min${domainNote}" "DarkYellow"
} else {
    Log "  Security log file not found -- may lack permissions" "DarkYellow"
}

Invoke-Skippable -Label "logon event query (30 days Security log)" -StatusFile $_logonStatusFile -Action {
    param($out, $sinceFT, $statusFile)
    $logSince = [DateTime]::FromFileTime($sinceFT)
    # 4634/4647 (Logoff) intentionally excluded -- extremely high volume on domain machines,
    # adds little forensic value vs. the 50-70% event count reduction.
    $logonIds = @(4624, 4625, 4648, 4672, 4720, 4726, 4738)
    $outFile  = "$out\02_logon_events.csv"

    try {
        $count     = 0
        $scanStart = Get-Date

        # Pipe directly to Export-Csv so each event is written to disk immediately.
        # If the job is skipped/killed mid-run, everything collected so far is preserved.
        # -MaxEvents 15000 caps worst-case runtime. Get-WinEvent returns newest-first.
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $logonIds
            StartTime = $logSince
        } -MaxEvents 15000 -ErrorAction Stop | ForEach-Object {
            $count++
            if ($count % 250 -eq 0) {
                $secs = [math]::Max(1, [int]((Get-Date) - $scanStart).TotalSeconds)
                $rate = [int]($count / $secs)
                "$count events found  (~${rate}/sec)" | Set-Content $statusFile
            }

            # Parse XML into hashtable once per event -- O(1) field lookups
            $dict = @{}
            try {
                ([xml]$_.ToXml()).Event.EventData.Data |
                    ForEach-Object { if ($_.Name) { $dict[$_.Name] = $_.'#text' } }
            } catch {}

            [PSCustomObject]@{
                Time        = $_.TimeCreated
                EventID     = $_.Id
                Meaning     = switch ($_.Id) {
                    4624 { "Successful Logon" }
                    4625 { "FAILED Logon -- $($dict['FailureReason'])" }
                    4648 { "Logon with Explicit Credentials (runas)" }
                    4672 { "Special Privilege Logon (Admin)" }
                    4720 { "User Account Created" }
                    4726 { "User Account Deleted" }
                    4738 { "User Account Changed" }
                }
                User        = "$($dict['TargetDomainName'])\$($dict['TargetUserName'])"
                LogonType   = $dict['LogonType']    # 2=Interactive 3=Network 10=RDP
                SourceIP    = $dict['IpAddress']
                Workstation = $dict['WorkstationName']
            }
        } | Export-Csv $outFile -NoTypeInformation -Append -Encoding UTF8

        "$count events collected (full run)" | Set-Content $statusFile
    } catch {
        "Access denied or no events: $_" | Set-Content $outFile -Encoding UTF8
    }
} -ArgumentList @($OutputPath, $since.ToFileTime(), $_logonStatusFile)

# --- Running Processes --------------------------------------------------------

Start-Section "RUNNING PROCESSES" "All processes with owner, path, and auto-flagging of known remote-access/spy tools"
$procs = Get-Process | Select-Object Id, Name, CPU, WorkingSet, Path, 
    @{N="Owner";E={ try{$_.GetOwner().User}catch{"?"} }},
    StartTime, MainWindowTitle |
    Sort-Object Name
Save "03_processes.txt" ($procs | Format-Table -AutoSize | Out-String)

# Flag suspicious process names
$suspiciousKeywords = @(
    # Remote access
    "anydesk","teamviewer","screenconnect","connectwise","logmein","ammyy","netsupport",
    "splashtop","rustdesk","zoho assist","dwservice","aeroadmin","gotoassist",
    "vnc","radmin","dameware","ultraviewer","parsec",
    # Tunneling / proxy
    "ngrok","frp","plink","putty","winpcap","npcap","wireshark","fiddler","proxifier",
    # Keyloggers / spyware
    "keylogger","ardamax","refog","revealer","spytech","actual keylogger",
    # Credential / exploitation tools
    "mimikatz","procdump","pwdump","lazagne","hashcat","wce","gsecdump",
    # Post-exploitation frameworks
    "psexec","paexec","cobaltstrike","meterpreter","empire","covenant","sliver","brute ratel",
    # Bulk data copy
    "rclone","restic","robocopy"
)
$flagged = $procs | Where-Object {
    $kw = $_; $suspiciousKeywords | Where-Object { $kw.Name -imatch $_ }
}
if ($flagged) {
    Save "03_processes_FLAGGED.txt" ($flagged | Format-Table -AutoSize | Out-String)
    Log "  *** FLAGGED SUSPICIOUS PROCESSES FOUND -- see 03_processes_FLAGGED.txt ***" "DarkYellow"
}
$script:indicators.SuspiciousProcessCount = ($flagged | Measure-Object).Count

# --- Services ----------------------------------------------------------------

Start-Section "SERVICES" "All services; flags those running from outside System32/Program Files"
Save "04_services_all.txt" (Get-Service | Sort-Object Status, Name | Format-Table -AutoSize | Out-String)
Save "04_services_running.txt" (
    Get-WmiObject Win32_Service | Where-Object { $_.State -eq "Running" } |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Sort-Object Name | Format-Table -AutoSize | Out-String
)

# Non-standard service paths (not in System32/Program Files)
$weirdServices = Get-WmiObject Win32_Service | Where-Object {
    $_.State -eq "Running" -and
    $_.PathName -and
    $_.PathName -notmatch 'System32|SysWOW64|Program Files|MsMpEng|svchost|Windows' -and
    $_.PathName -notmatch '^"?[A-Z]:\\Windows'
}
if ($weirdServices) {
    Save "04_services_SUSPICIOUS.txt" ($weirdServices | Select-Object Name, PathName, StartName | Format-Table -AutoSize | Out-String)
    Log "  *** Services running from unusual paths -- see 04_services_SUSPICIOUS.txt ***" "DarkYellow"
}

# --- Scheduled Tasks ----------------------------------------------------------

Start-Section "SCHEDULED TASKS" "Active tasks; flags those running scripts or executables from AppData/Temp"
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
    Select-Object TaskName, TaskPath, State,
        @{N="Actions";E={ ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; " }},
        @{N="Triggers";E={ ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join "; " }}
Save "05_scheduled_tasks.txt" ($tasks | Format-Table -AutoSize | Out-String)

$weirdTasks = $tasks | Where-Object {
    $_.Actions -match 'AppData|Temp|Downloads|%APPDATA%|\.ps1|\.vbs|\.bat|\.cmd|powershell|wscript|cscript|mshta|regsvr32|rundll32|cmd\.exe /c'
}
if ($weirdTasks) {
    Save "05_scheduled_tasks_SUSPICIOUS.txt" ($weirdTasks | Format-Table -AutoSize | Out-String)
    Log "  *** Suspicious scheduled task actions found ***" "DarkYellow"
}

# --- Startup Items ------------------------------------------------------------

Start-Section "STARTUP / AUTORUN" "Registry Run keys and startup folders -- common persistence locations"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
$autoruns = foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty $key
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            [PSCustomObject]@{ Key = $key; Name = $_.Name; Value = $_.Value }
        }
    }
}
Save "06_autoruns_registry.txt" ($autoruns | Format-Table -AutoSize | Out-String)

# Startup folder contents
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$startupItems = foreach ($folder in $startupFolders) {
    if (Test-Path $folder) { Get-ChildItem $folder -Force }
}
Save "06_startup_folders.txt" ($startupItems | Format-Table FullName, LastWriteTime, Length -AutoSize | Out-String)

# --- Network State ------------------------------------------------------------

Start-Section "NETWORK STATE" "Active connections, external IPs, DNS/ARP/routing, firewall rules, proxies, tunnels, BITS (CIS 4.1, 4.4/4.5 firewall and network config)"
Save "07_netstat.txt"        (netstat -ano 2>&1)
Save "07_dns_cache.txt"      (ipconfig /displaydns 2>&1)
Save "07_arp_cache.txt"      (arp -a 2>&1)
Save "07_routing_table.txt"  (route print 2>&1)
Save "07_network_adapters.txt"(Get-NetAdapter | Format-Table -AutoSize | Out-String)
Save "07_wifi_profiles.txt"  (netsh wlan show profiles 2>&1)

# -- TCP connections enriched with process names ----------------------------
$allTCP = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
        @{N="PID";E={$_.OwningProcess}},
        @{N="Process";E={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }},
        @{N="ProcessPath";E={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path }}
Save "07_tcp_all.txt" ($allTCP | Sort-Object State, RemoteAddress | Format-Table -AutoSize | Out-String)

# -- UDP endpoints (often overlooked; used by DNS tunneling, exfil tools) --
$udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort,
        @{N="PID";E={$_.OwningProcess}},
        @{N="Process";E={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }}
Save "07_udp_endpoints.txt" ($udpEndpoints | Sort-Object LocalPort | Format-Table -AutoSize | Out-String)

# -- External established connections (flag immediately) --------------------
$externalConns = $allTCP | Where-Object {
    $_.State -eq "Established" -and
    $_.RemoteAddress -and
    $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|^::$)'
}
if ($externalConns) {
    # Attempt reverse DNS for context -- run quietly, don't block on failures
    $enrichedExternal = $externalConns | ForEach-Object {
        $rdns = try { [System.Net.Dns]::GetHostEntry($_.RemoteAddress).HostName } catch { "no-rdns" }
        [PSCustomObject]@{
            Process       = $_.Process
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            ReverseDNS    = $rdns
            PID           = $_.PID
            ProcessPath   = $_.ProcessPath
        }
    }
    Save "07_connections_EXTERNAL.txt" ($enrichedExternal | Format-Table -AutoSize | Out-String)
    Log "  *** $($externalConns.Count) external established connection(s) -- see 07_connections_EXTERNAL.txt ***" "DarkYellow"
    $script:indicators.ExternalConnectionCount = $externalConns.Count
}

# -- Suspicious listening port analysis ------------------------------------
# Workstations should not be listening on most ports; flag unusual listeners.
$normalListenerPorts = @(
    135,   # RPC endpoint mapper
    445,   # SMB
    139,   # NetBIOS
    5040,  # RPC (Windows 10)
    7680,  # Delivery Optimization
    1900,  # SSDP/UPnP
    5353,  # mDNS
    3389   # RDP (flagged separately below)
    # Note: ephemeral range 49152-65535 excluded by $port -lt 49152 check below
)
$listeners = $allTCP | Where-Object { $_.State -eq "Listen" }
$suspiciousListeners = $listeners | Where-Object {
    $port = $_.LocalPort
    $proc = $_.Process
    # Flag low+mid ports that aren't in the normal list
    $port -lt 49152 -and
    $port -notin $normalListenerPorts -and
    $proc -notmatch '^(svchost|lsass|services|System|wininit|spoolsv|MsMpEng|SearchIndexer|OneDrive|Teams|Zoom|slack|discord)$'
}
Save "07_listeners_all.txt" ($listeners | Sort-Object LocalPort | Format-Table -AutoSize | Out-String)
if ($suspiciousListeners) {
    Save "07_listeners_SUSPICIOUS.txt" ($suspiciousListeners | Sort-Object LocalPort | Format-Table -AutoSize | Out-String)
    Log "  *** Unusual listening ports found -- see 07_listeners_SUSPICIOUS.txt ***" "DarkYellow"
}

# Flag RDP specifically (3389 listening = remote desktop enabled -- verify it's intended)
$rdpListener = $listeners | Where-Object { $_.LocalPort -eq 3389 }
if ($rdpListener) {
    Log "  *** RDP (port 3389) is LISTENING -- remote desktop is enabled on this machine ***" "DarkYellow"
    Save "07_rdp_enabled.txt" ($rdpListener | Format-Table -AutoSize | Out-String)
}

# -- Known suspicious / C2 port patterns ----------------------------------
# These ports appear in common RAT, backdoor, and tunneling tools
$knownBadPorts = @{
    1080  = "SOCKS proxy / common RAT default"
    4444  = "Metasploit default listener"
    4445  = "Metasploit alt listener"
    5555  = "Android ADB / common RAT"
    6666  = "Common IRC/RAT port"
    6667  = "IRC (C2 via IRC)"
    6697  = "IRC over TLS"
    7777  = "Common RAT / reverse shell"
    8888  = "Common backdoor / Jupyter (unusual on workstation)"
    9001  = "Tor ORPort"
    9050  = "Tor SOCKSPort"
    9051  = "Tor ControlPort"
    9150  = "Tor Browser SOCKSPort"
    31337 = "Classic backdoor (Elite)"
    12345 = "Classic backdoor (NetBus)"
    27374 = "SubSeven RAT"
    1337  = "Common hacker/RAT port"
}
$badPortHits = $allTCP | Where-Object {
    ($_.LocalPort  -in $knownBadPorts.Keys -or $_.RemotePort -in $knownBadPorts.Keys) -and
    $_.State -in @("Listen","Established")
} | ForEach-Object {
    $matchedPort = if ($_.LocalPort -in $knownBadPorts.Keys) { $_.LocalPort } else { $_.RemotePort }
    [PSCustomObject]@{
        Process     = $_.Process
        LocalPort   = $_.LocalPort
        RemoteAddr  = $_.RemoteAddress
        RemotePort  = $_.RemotePort
        State       = $_.State
        FlaggedPort = $matchedPort
        Reason      = $knownBadPorts[$matchedPort]
    }
}
if ($badPortHits) {
    Save "07_known_bad_ports_FLAGGED.txt" ($badPortHits | Format-Table -AutoSize | Out-String)
    Log "  *** Known suspicious port(s) in use -- see 07_known_bad_ports_FLAGGED.txt ***" "DarkYellow"
}

# -- Virtual / TAP adapters (VPN, tunnel tools, packet sniffers) -----------
$virtualAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -imatch 'TAP|TUN|Virtual|WireGuard|OpenVPN|Loopback|ZeroTier|Hamachi|Radmin|Wintun|npcap|npf' -or
    $_.Name -imatch 'TAP|TUN|VPN|Hamachi|ZeroTier|Radmin'
}
if ($virtualAdapters) {
    Save "07_virtual_adapters_FLAGGED.txt" ($virtualAdapters | Format-Table Name, InterfaceDescription, Status, MacAddress -AutoSize | Out-String)
    Log "  *** Virtual/TAP network adapters found (VPN or tunnel tool) -- see 07_virtual_adapters_FLAGGED.txt ***" "DarkYellow"
    $script:indicators.VirtualAdaptersFound = @($virtualAdapters.Name)
} else {
    Log "  No virtual/TAP adapters found"
}

# -- netsh portproxy -- silent port-forwarding / tunneling rules ------------
$portProxy = netsh interface portproxy show all 2>&1
Save "07_portproxy.txt" ($portProxy | Out-String)
if ($portProxy -match '\d+\.\d+\.\d+\.\d+|\*') {
    Log "  *** netsh portproxy rules exist -- traffic may be silently forwarded ***" "DarkYellow"
} else {
    Log "  No netsh portproxy rules found"
}

# -- Windows Firewall state and suspicious rules ----------------------------
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked
Save "07_firewall_profiles.txt" ($fwProfiles | Format-Table -AutoSize | Out-String)

$disabledProfiles = $fwProfiles | Where-Object { $_.Enabled -eq $false }
if ($disabledProfiles) {
    Log "  *** Firewall DISABLED on profile(s): $($disabledProfiles.Name -join ', ') ***" "DarkYellow"
    $script:indicators.FirewallDisabledProfiles = @($disabledProfiles.Name)
}

# Firewall rules that allow all inbound traffic (Action=Allow, Direction=Inbound, no remote address filter)
$suspiciousFWRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Profile -ne 'Domain' } |   # skip domain-policy rules
    Select-Object DisplayName, Direction, Action, Profile, Enabled,
        @{N="Program";  E={ ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program }},
        @{N="LocalPort"; E={ ($_ | Get-NetFirewallPortFilter       -ErrorAction SilentlyContinue).LocalPort }}
Save "07_firewall_inbound_allow_rules.txt" ($suspiciousFWRules | Format-Table -AutoSize | Out-String)

# Flag rules allowing Any port from Any remote address
$broadFWRules = $suspiciousFWRules | Where-Object {
    $_.LocalPort -in @("Any","*","0-65535") -or -not $_.LocalPort
}
if ($broadFWRules) {
    Save "07_firewall_broad_rules_FLAGGED.txt" ($broadFWRules | Format-Table -AutoSize | Out-String)
    Log "  *** Broad inbound firewall allow-rules found -- see 07_firewall_broad_rules_FLAGGED.txt ***" "Yellow"
}

# -- Proxy settings (system-wide and per-user WinINET) --------------------
$proxyReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
$proxyInfo = [PSCustomObject]@{
    ProxyEnabled  = $proxyReg.ProxyEnable
    ProxyServer   = $proxyReg.ProxyServer
    ProxyOverride = $proxyReg.ProxyOverride
    AutoConfigURL = $proxyReg.AutoConfigURL
}
Save "07_proxy_settings.txt" ($proxyInfo | Format-List | Out-String)

$winhttpProxy = netsh winhttp show proxy 2>&1
Add-Content "$OutputPath\07_proxy_settings.txt" ("`n[WinHTTP System Proxy]`n" + ($winhttpProxy | Out-String))

if ($proxyReg.ProxyEnable -eq 1 -or ($proxyReg.ProxyServer -and $proxyReg.ProxyServer -ne "")) {
    Log "  *** User proxy is ENABLED: $($proxyReg.ProxyServer) -- potential MITM or traffic interception ***" "DarkYellow"
} elseif ($proxyReg.AutoConfigURL) {
    Log "  *** Proxy auto-config (PAC) URL set: $($proxyReg.AutoConfigURL) ***" "Yellow"
} else {
    Log "  No proxy configured"
}

# -- BITS (Background Intelligent Transfer Service) jobs -------------------
# BITS is legitimately used by Windows Update; it's also abused for stealthy exfil
try {
    $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction Stop |
        Select-Object DisplayName, TransferType, JobState, BytesTotal, BytesTransferred,
            CreationTime, ModificationTime, OwnerAccount,
            @{N="Files";E={ ($_.FileList | ForEach-Object { "$($_.LocalName) → $($_.RemoteName)" }) -join "; " }}
    Save "07_bits_jobs.txt" ($bitsJobs | Format-Table -AutoSize | Out-String)
    $suspiciousBITS = $bitsJobs | Where-Object {
        $_.TransferType -eq "Upload" -or
        $_.Files -imatch 'http|ftp' -and $_.Files -notmatch 'microsoft|windowsupdate|msftconnecttest'
    }
    if ($suspiciousBITS) {
        Save "07_bits_SUSPICIOUS.txt" ($suspiciousBITS | Format-Table -AutoSize | Out-String)
        Log "  *** Suspicious BITS transfer jobs found -- see 07_bits_SUSPICIOUS.txt ***" "DarkYellow"
    } else {
        Log "  BITS jobs: $($bitsJobs.Count) found, none flagged"
    }
} catch {
    Save "07_bits_jobs.txt" "Could not query BITS: $_"
}

# -- RDP configuration ----------------------------------------------------
$rdpRegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpDeny   = try { Get-ItemPropertyValue $rdpRegKey -Name fDenyTSConnections -ErrorAction Stop } catch { $null }
$rdpOn     = ($null -ne $rdpDeny -and $rdpDeny -eq 0)
$nlsKey    = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$nlaOn     = try { [bool](Get-ItemPropertyValue $nlsKey -Name UserAuthentication -ErrorAction Stop) } catch { $null }
$rdpFWRules = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -and $_.Direction -eq "Inbound" }

$script:indicators.RDPEnabled  = $rdpOn
$script:indicators.NLARequired = $nlaOn

[ordered]@{
    RDPEnabled         = $rdpOn
    NLARequired        = $nlaOn
    FirewallRulesExist = [bool]$rdpFWRules
    FirewallRuleNames  = @($rdpFWRules.DisplayName)
} | ConvertTo-Json | Set-Content "$OutputPath\07_rdp_settings.json" -Encoding UTF8

if ($rdpOn) { Log "  *** RDP is ENABLED via registry -- remote access is active ***" "DarkYellow" }
else        { Log "  RDP disabled (fDenyTSConnections = 1)" }

# -- Windows Defender / AV status -----------------------------------------
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    $script:indicators.DefenderRealtimeEnabled = $defenderStatus.RealTimeProtectionEnabled

    $quickScanAge = $defenderStatus.QuickScanAge
    $fullScanAge  = $defenderStatus.FullScanAge
    # FullScanAge returns Int32.MaxValue if never run
    $fullScanAgeDisplay  = if ($fullScanAge  -ge [int32]::MaxValue) { "Never" } else { "$fullScanAge days" }
    $quickScanAgeDisplay = if ($quickScanAge -ge [int32]::MaxValue) { "Never" } else { "$quickScanAge days" }

    [ordered]@{
        RealTimeProtection    = $defenderStatus.RealTimeProtectionEnabled
        AntivirusEnabled      = $defenderStatus.AntivirusEnabled
        AMServiceEnabled      = $defenderStatus.AMServiceEnabled
        BehaviorMonitor       = $defenderStatus.BehaviorMonitorEnabled
        TamperProtection      = $defenderStatus.IsTamperProtected
        SignatureAgeDays       = $defenderStatus.AntivirusSignatureAge
        SignatureVersion       = $defenderStatus.AntivirusSignatureVersion
        LastQuickScan         = $defenderStatus.QuickScanStartTime
        LastQuickScanAgeDays  = $quickScanAgeDisplay
        LastQuickScanResult   = $defenderStatus.QuickScanEndTime
        LastFullScan          = $defenderStatus.FullScanStartTime
        LastFullScanAgeDays   = $fullScanAgeDisplay
        LastFullScanResult    = $defenderStatus.FullScanEndTime
    } | ConvertTo-Json | Set-Content "$OutputPath\07_defender_status.json" -Encoding UTF8

    if (-not $defenderStatus.RealTimeProtectionEnabled) {
        Log "  *** Defender real-time protection is DISABLED ***" "DarkYellow"
    } else {
        Log "  Defender: real-time ON | signatures $($defenderStatus.AntivirusSignatureAge) days old | last quick scan: $quickScanAgeDisplay ago | last full scan: $fullScanAgeDisplay ago"
    }
    if ($defenderStatus.AntivirusSignatureAge -gt 7) {
        Log "  *** Defender signatures are $($defenderStatus.AntivirusSignatureAge) days old -- definitions may be stale ***" "DarkYellow"
    }

    # CIS 10.7 -- Behavior-based anti-malware
    $script:cisIG1.DefenderBehaviorMonitor = $defenderStatus.BehaviorMonitorEnabled
    if (-not $defenderStatus.BehaviorMonitorEnabled) {
        Log "  [CIS 10.7] *** FLAGGED: Defender behavior monitoring is DISABLED ***" "DarkYellow"
    } else {
        Log "  [CIS 10.7] Behavior monitoring enabled" "DarkGray"
    }

    # Defender exclusion list -- attackers commonly add exclusions to hide malware
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $exclPaths = @($mpPref.ExclusionPath)
        $exclExts  = @($mpPref.ExclusionExtension)
        $exclProcs = @($mpPref.ExclusionProcess)

        $exclReport = [ordered]@{
            ExclusionPaths      = $exclPaths
            ExclusionExtensions = $exclExts
            ExclusionProcesses  = $exclProcs
        }
        $exclReport | ConvertTo-Json -Depth 3 |
            Set-Content "$OutputPath\07_defender_exclusions.json" -Encoding UTF8

        $totalExcl = @($exclPaths + $exclExts + $exclProcs | Where-Object { $_ }).Count
        $script:cisIG1.DefenderExclusions = @($exclPaths + $exclExts + $exclProcs | Where-Object { $_ })
        if ($totalExcl -gt 0) {
            Log "  *** $totalExcl Defender exclusion(s) configured -- review 07_defender_exclusions.json ***" "DarkYellow"
            $exclPaths | Where-Object { $_ } | ForEach-Object { Log "    Excluded path: $_" "DarkYellow" }
            $exclProcs | Where-Object { $_ } | ForEach-Object { Log "    Excluded proc: $_" "DarkYellow" }
        } else {
            Log "  No Defender exclusions configured" "DarkGray"
        }

        # CIS 10.4 -- Removable drive scanning
        $script:cisIG1.RemovableDriveScan = -not $mpPref.DisableRemovableDriveScanning
        if ($mpPref.DisableRemovableDriveScanning) {
            Log "  [CIS 10.4] *** FLAGGED: Defender removable drive scanning is DISABLED ***" "DarkYellow"
        } else {
            Log "  [CIS 10.4] Removable drive scanning enabled" "DarkGray"
        }
    } catch {
        Log "  Could not query Defender preferences: $_" "DarkGray"
    }
} catch {
    Log "  Could not query Defender (may not be primary AV): $_" "DarkGray"
}

# -- Third-party AV via Windows Security Center (SecurityCenter2) ----------
try {
    $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop
    $avReport = $avProducts | ForEach-Object {
        # productState nibble layout (6 hex chars): TTRRDD
        #   T (pos 0-1): product type
        #   R (pos 2):   real-time state -- '1'=Active, '0'=Inactive
        #   R (pos 3):   sub-state (ignore)
        #   D (pos 4):   definitions   -- '0'=UpToDate, '1'=OutOfDate
        $hex      = '{0:X6}' -f [int]$_.productState
        $active   = $hex[2] -eq '1'
        $upToDate = $hex[4] -eq '0'
        [PSCustomObject]@{
            Product         = $_.displayName
            Active          = $active
            DefinitionsOK   = $upToDate
            PathToExe       = $_.pathToSignedProductExe
            StateHex        = "0x$hex"
            Timestamp       = $_.timestamp
        }
    }
    $avReport | ConvertTo-Json -Depth 3 | Set-Content "$OutputPath\07_av_products.json" -Encoding UTF8
    foreach ($av in $avReport) {
        $status = if ($av.Active) { "ACTIVE" } else { "INACTIVE" }
        $defs   = if ($av.DefinitionsOK) { "defs OK" } else { "DEFS OUT OF DATE" }
        Log "  AV: $($av.Product) -- $status, $defs"
        if (-not $av.Active) {
            Log "  *** $($av.Product) is registered but INACTIVE ***" "DarkYellow"
        }
    }
    if (-not $avProducts) {
        Log "  No AV products registered with Windows Security Center" "DarkYellow"
    }
} catch {
    Log "  Could not query SecurityCenter2 (domain policy may suppress it): $_" "DarkGray"
}

# --- Installed Software -------------------------------------------------------

Start-Section "INSTALLED SOFTWARE" "All installed programs with dates; flags RATs, keyloggers, tunnel tools, bulk-copy utilities (CIS 2.1 software inventory)"
$installed = @(
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object InstallDate -Descending

Save "08_installed_software.txt" ($installed | Format-Table -AutoSize | Out-String)

# Flag remote access / surveillance tools
$remoteTools = @(
    # Remote access (expanded to match both scripts)
    "anydesk","teamviewer","screenconnect","connectwise","logmein","gotomypc","splashtop",
    "parsec","radmin","dameware","pcAnywhere","remote desktop","netsupport","ultraviewer",
    "rustdesk","zoho assist","dwservice","aeroadmin","gotoassist","goto resolve",
    "chrome remote desktop","remote utilities","ammyy",
    # Surveillance / keyloggers
    "keylogger","ardamax","revealer","refog","spector","activity monitor",
    # Tunneling / exfil
    "ngrok","frp","pagekite","telebit","rclone","duplicati","restic",
    # Network tools
    "wireshark","nmap","advanced ip scanner","angry ip",
    # Transfer / FTP
    "putty","winscp","filezilla","cyberduck"
)
$flaggedSoftware = $installed | Where-Object {
    $dn = $_.DisplayName
    $remoteTools | Where-Object { $dn -imatch $_ }
}
if ($flaggedSoftware) {
    Save "08_installed_software_FLAGGED.txt" ($flaggedSoftware | Format-Table -AutoSize | Out-String)
    Log "  *** Flagged software installed -- see 08_installed_software_FLAGGED.txt ***" "DarkYellow"
}
$script:indicators.RemoteAccessSoftwareHits = @($flaggedSoftware | Select-Object -ExpandProperty DisplayName)

# --- USB / Removable Device History ------------------------------------------

Start-Section "USB DEVICE HISTORY" "Every USB storage device ever connected via registry (USBSTOR) -- removable media / data exfil tracking (CIS 3.6)"
$usbHistory = @()
try {
    foreach ($class in Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -ErrorAction Stop) {
        foreach ($inst in Get-ChildItem $class.PSPath -ErrorAction SilentlyContinue) {
            $dev = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
            $lastArrival = ""
            try {
                # DEVPKEY_Device_LastArrivalDate — REG_BINARY FILETIME stored under Properties sub-key
                $tsProp = Get-ItemProperty -LiteralPath "$($inst.PSPath)\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0065" -ErrorAction Stop
                $raw = ($tsProp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -First 1).Value
                if ($raw -and $raw.Count -ge 8) {
                    $ft = [BitConverter]::ToInt64([byte[]]$raw, 0)
                    $lastArrival = [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
                }
            } catch {}
            $usbHistory += [PSCustomObject]@{
                FriendlyName = $dev.FriendlyName
                Mfg          = $dev.Mfg
                DeviceID     = $inst.PSChildName
                LastArrival  = $lastArrival
            }
        }
    }
} catch {
    $usbHistory += [PSCustomObject]@{ FriendlyName = "Could not read USBSTOR: $_"; Mfg=""; DeviceID=""; LastArrival="" }
}
$script:indicators.UsbDeviceCount = $usbHistory.Count
Save "09_usb_history.txt" ($usbHistory | Format-Table -AutoSize | Out-String)

# --- Per-User Evidence --------------------------------------------------------

Start-Section "PER-USER EVIDENCE" "Browser history, recent files, cloud sync, PowerShell history, jump lists -- per profile"

foreach ($profile in $profiles) {
    $user    = $profile.Name
    $userHome    = $profile.FullName
    $userDir = "$OutputPath\user_$user"
    New-Item -ItemType Directory -Force -Path $userDir | Out-Null

    Log "`n  === Collecting for user: $user ===" "Magenta"

    # -- Recent files (Shell:Recent) --------------------------------------
    $recentPath = "$userHome\AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Get-ChildItem $recentPath -Force |
            Select-Object Name, LastWriteTime, Target |
            Sort-Object LastWriteTime -Descending |
            Format-Table -AutoSize |
            Out-String |
            Set-Content "$userDir\recent_files.txt" -Encoding UTF8
        Log "    Saved: recent_files.txt"
    }

    # -- Clipboard history location ---------------------------------------
    # Windows 10 1809+ stores clipboard history - note location only
    $clipPath = "$userHome\AppData\Local\ConnectedDevicesPlatform"
    if (Test-Path $clipPath) {
        Get-ChildItem $clipPath -Recurse -Force -Filter "*.db" -ErrorAction SilentlyContinue |
            ForEach-Object { CopyFile $_.FullName "user_${user}_clipboard_$($_.Name)" }
    }

    # -- Cloud sync folders -----------------------------------------------
    $cloudPaths = @(
        "$userHome\OneDrive",
        "$userHome\Dropbox",
        "$userHome\Google Drive",
        "$userHome\Box Sync",
        "$userHome\iCloudDrive"
    )
    $foundCloud = $cloudPaths | Where-Object { Test-Path $_ }
    if ($foundCloud) {
        $foundCloud | Set-Content "$userDir\cloud_sync_folders_FOUND.txt" -Encoding UTF8
        Log "    *** Cloud sync folders present: $($foundCloud -join ', ') ***" "DarkYellow"
    }

    # -- PowerShell history -----------------------------------------------
    $psHistory = "$userHome\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    CopyFile $psHistory "user_${user}_powershell_history.txt"

    # -- CMD history (from registry) --------------------------------------
    $cmdHivePath = "Registry::HKEY_USERS"
    # We'll capture it via the profile's NTUSER.DAT hive loading approach -- just note the path
    $cmdHistRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    # Only works for currently logged-in user; note others require hive mounting
    if ($user -eq $env:USERNAME -and (Test-Path $cmdHistRegPath)) {
        Get-ItemProperty $cmdHistRegPath |
            Out-String |
            Set-Content "$userDir\run_mru_history.txt" -Encoding UTF8
        Log "    Saved: run_mru_history.txt"
    }

    # -- Browser: Google Chrome -------------------------------------------
    $chromePaths = @(
        "$userHome\AppData\Local\Google\Chrome\User Data\Default",
        "$userHome\AppData\Local\Google\Chrome\User Data\Profile 1"
    )
    foreach ($cp in $chromePaths) {
        if (Test-Path $cp) {
            $profileLabel = ($cp -split "\\")[-1] -replace " ","_"
            New-Item -ItemType Directory -Force -Path "$userDir\Chrome_$profileLabel" | Out-Null

            # Copy SQLite databases (Chrome must be closed for clean copy, but we try regardless)
            # Cookies, Login Data, and Web Data (autofill/cards) intentionally excluded -- privacy scope
            foreach ($dbFile in @("History","Bookmarks","Preferences","Top Sites","Shortcuts")) {
                $src = "$cp\$dbFile"
                if (Test-Path $src) {
                    Copy-Item $src "$userDir\Chrome_$profileLabel\$dbFile" -Force -ErrorAction SilentlyContinue
                }
            }
            Log "    Copied Chrome profile: $profileLabel (History, Bookmarks) -- open History with DB Browser for SQLite"
            # Note: URL keyword analysis runs in the next section via binary ASCII extraction (no sqlite3 needed)
        }
    }

    # -- Browser: Microsoft Edge ------------------------------------------
    $edgePath = "$userHome\AppData\Local\Microsoft\Edge\User Data\Default"
    if (Test-Path $edgePath) {
        New-Item -ItemType Directory -Force -Path "$userDir\Edge_Default" | Out-Null
            # Cookies, Login Data, and Web Data intentionally excluded -- privacy scope
            foreach ($dbFile in @("History","Bookmarks","Preferences")) {
            $src = "$edgePath\$dbFile"
            if (Test-Path $src) {
                Copy-Item $src "$userDir\Edge_Default\$dbFile" -Force -ErrorAction SilentlyContinue
            }
        }
        Log "    Copied Edge profile data -- open History with DB Browser for SQLite"
    }

    # -- Browser: Firefox ------------------------------------------------
    $ffBase = "$userHome\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (Test-Path $ffBase) {
        Get-ChildItem $ffBase -Directory | ForEach-Object {
            $ffProfile = $_.FullName
            $ffLabel   = $_.Name
            New-Item -ItemType Directory -Force -Path "$userDir\Firefox_$ffLabel" | Out-Null

            # cookies.sqlite, formhistory.sqlite, logins.json, key4.db intentionally excluded -- privacy scope
            foreach ($dbFile in @("places.sqlite","downloads.sqlite")) {
                $src = "$ffProfile\$dbFile"
                if (Test-Path $src) {
                    Copy-Item $src "$userDir\Firefox_$ffLabel\$dbFile" -Force -ErrorAction SilentlyContinue
                }
            }
            Log "    Copied Firefox profile: $ffLabel -- open .sqlite files with DB Browser for SQLite"
        }
    }

    # -- Windows Search history -------------------------------------------
    $searchHist = "$userHome\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
    if (Test-Path $searchHist) {
        New-Item -ItemType Directory -Force -Path "$userDir\jump_lists" | Out-Null
        Get-ChildItem $searchHist -Force -ErrorAction SilentlyContinue |
            Copy-Item -Destination "$userDir\jump_lists\" -Force -ErrorAction SilentlyContinue
        Log "    Copied Jump Lists / AutomaticDestinations"
    }

    # -- Outlook/Mail artifacts -------------------------------------------
    $outlookPath = "$userHome\AppData\Local\Microsoft\Outlook"
    if (Test-Path $outlookPath) {
        Get-ChildItem $outlookPath -Filter "*.ost" -ErrorAction SilentlyContinue |
            Select-Object Name, LastWriteTime, @{N="SizeMB";E={[math]::Round($_.Length/1MB,1)}} |
            Format-Table -AutoSize |
            Out-String |
            Set-Content "$userDir\outlook_ost_info.txt" -Encoding UTF8
        Log "    Noted Outlook .ost files (large = active mailbox)"
    }

    # -- Large/unusual files in user folders -----------------------------
    # Run as a background job -- on large profiles this can take several minutes
    $_largeFileStatus = "$env:TEMP\ce_largefile_status.tmp"
    Invoke-Skippable -Label "large file scan ($user)" -StatusFile $_largeFileStatus -Action {
        param($h, $ud, $statusFile)
        $count    = 0
        $outFile  = "$ud\large_files_over50MB.csv"
        Get-ChildItem $h -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 50MB } |
            ForEach-Object {
                $count++
                if ($count % 10 -eq 0) { "$count large files found so far..." | Set-Content $statusFile }
                [PSCustomObject]@{
                    SizeMB        = [math]::Round($_.Length / 1MB, 1)
                    LastWriteTime = $_.LastWriteTime
                    FullName      = $_.FullName
                }
            } | Export-Csv $outFile -NoTypeInformation -Append -Encoding UTF8
        "$count large files total" | Set-Content $statusFile
    } -ArgumentList @($userHome, $userDir, $_largeFileStatus)

    # -- Temp folder anomalies --------------------------------------------
    $tempPaths = @("$userHome\AppData\Local\Temp", "$env:SystemRoot\Temp")
    foreach ($tp in $tempPaths) {
        if (Test-Path $tp) {
            Get-ChildItem $tp -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -imatch '\.(exe|dll|ps1|vbs|bat|cmd|msi|jar)$' } |
                Select-Object FullName, LastWriteTime, @{N="SizeMB";E={[math]::Round($_.Length/1MB,2)}} |
                Format-Table -AutoSize |
                Out-String |
                Add-Content "$userDir\temp_executables_SUSPICIOUS.txt" -Encoding UTF8
        }
    }
    if (Test-Path "$userDir\temp_executables_SUSPICIOUS.txt") {
        Log "    *** Executables found in Temp -- see temp_executables_SUSPICIOUS.txt ***" "DarkYellow"
    }
}

# --- Browser Keyword Analysis -------------------------------------------------
#
# Reads Chrome/Edge History binaries as ASCII and regex-extracts all URLs without
# needing sqlite3. Scans every URL against 60+ keywords covering RAT tools,
# webcam hacking, exploitation, job searching, and data-upload services.
# Catches INTENT before tools are installed -- often the most valuable finding.

Start-Section "BROWSER KEYWORD ANALYSIS" "URL extraction from History binaries + 60+ keyword flags -- no sqlite3 required"

$browserKeywords = @(
    # Remote access tools (researching how to install or use)
    "teamviewer","anydesk","screenconnect","connectwise","logmein","splashtop",
    "rustdesk","zoho assist","dwservice","aeroadmin","gotoassist","goto resolve",
    "chrome remote desktop","remote utilities","ammyy","ultravnc","tightvnc","realvnc",
    # Exploitation / hacking
    "mimikatz","hashcat","meterpreter","reverse shell","credential dump",
    "password dump","privilege escalation","firewall bypass","port forwarding",
    "kali linux","metasploit","burp suite","exploit",
    # Webcam-specific
    "webcam hack","access webcam remotely","remote webcam","spy camera",
    "ip webcam","ispy","blue iris","webcam viewer","spy cam",
    # Virtual camera / streaming to another device
    "obs virtual camera","manycam","youcam","webcamoid","droidcam","epoccam","ivcam",
    # Data exfil upload sites
    "wetransfer","sendspace","mega.nz","anonfiles","gofile.io","transfer.sh",
    "file.io","litterbox","catbox","pixeldrain",
    # Anonymity / dark web
    "tor browser","protonmail","tutanota","guerrillamail","tempmail","10minutemail",
    # Job searching (context for potential data theft before leaving)
    "linkedin.com/jobs","indeed.com","glassdoor.com","ziprecruiter","monster.com"
)

$kwHits = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($profile in $profiles) {
    $user = $profile.Name
    $histPaths = @(
        @{ Path = "$($profile.FullName)\AppData\Local\Google\Chrome\User Data\Default\History";  Browser = "Chrome" },
        @{ Path = "$($profile.FullName)\AppData\Local\Google\Chrome\User Data\Profile 1\History"; Browser = "Chrome-P1" },
        @{ Path = "$($profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\History";  Browser = "Edge" }
    )

    foreach ($entry in $histPaths) {
        if (-not (Test-Path $entry.Path)) { continue }
        try {
            $tmp = "$env:TEMP\hist_kw_$(Get-Random).bin"
            Copy-Item $entry.Path $tmp -Force -ErrorAction Stop

            $bytes = [System.IO.File]::ReadAllBytes($tmp)
            $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
            $urls  = [regex]::Matches($text, 'https?://[a-zA-Z0-9\.\-_/:%\?\&=\+#~@,;]+') |
                     ForEach-Object { $_.Value }

            Remove-Item $tmp -Force -ErrorAction SilentlyContinue

            foreach ($url in $urls) {
                $matched = $browserKeywords | Where-Object { $url -imatch [regex]::Escape($_) }
                if (-not $matched) { continue }
                $domain = try { ([uri]$url).Host } catch { "unknown" }
                foreach ($kw in $matched) {
                    $kwHits.Add([PSCustomObject]@{
                        User    = $user
                        Browser = $entry.Browser
                        Keyword = $kw
                        Domain  = $domain
                        URL     = $url.Substring(0, [Math]::Min($url.Length, 300))
                    })
                }
            }
            Log "  $($entry.Browser) for $user`: $($urls.Count) URLs scanned"
        } catch {
            Log "  Could not scan $($entry.Browser) for $user`: $_" "DarkGray"
        }
    }
}

$script:indicators.BrowserKeywordHitCount   = $kwHits.Count
$script:indicators.BrowserKeywordHitDomains = @($kwHits | Select-Object -ExpandProperty Domain -Unique)

if ($kwHits.Count -gt 0) {
    $kwHits | Sort-Object User, Keyword |
        Export-Csv "$OutputPath\09b_browser_keyword_FLAGGED.csv" -NoTypeInformation -Encoding UTF8

    # Summary: count per keyword, which users hit it
    $kwHits | Group-Object Keyword | Sort-Object Count -Descending |
        Select-Object Name, Count, @{N="Users";E={($_.Group.User | Select-Object -Unique) -join ", "}} |
        Format-Table -AutoSize | Out-String |
        Set-Content "$OutputPath\09b_browser_keyword_summary.txt" -Encoding UTF8

    Log "  *** $($kwHits.Count) keyword hits across $($kwHits | Select-Object -ExpandProperty Domain -Unique | Measure-Object | Select-Object -ExpandProperty Count) domains -- see 09b_browser_keyword_FLAGGED.csv ***" "DarkYellow"
} else {
    Log "  No suspicious keyword hits found in browser history" "Green"
}

# --- Event Logs (System & Application) ---------------------------------------

Start-Section "EVENT LOGS" "Security, System, Application -- last 7 days, max 2000 events each (CIS 8.2 audit log export)"
$logSince = (Get-Date).AddDays(-7)

# Pre-query: show size of each log so user knows what to expect
foreach ($evtLogName in @("Security","System","Application")) {
    $evtPath = "$env:SystemRoot\System32\winevt\Logs\$evtLogName.evtx"
    if (Test-Path $evtPath) {
        $mb = [math]::Round((Get-Item $evtPath).Length / 1MB, 0)
        Log "  $evtLogName log: ${mb}MB on disk" "DarkGray"
    }
}

$_evtStatusFile = "$env:TEMP\ce_evtlog_status.tmp"

Invoke-Skippable -Label "event log export (Security + System + Application)" -StatusFile $_evtStatusFile -Action {
    param($out, $sinceFT, $statusFile)
    $logSince = [DateTime]::FromFileTime($sinceFT)

    foreach ($evtLog in @("Security","System","Application")) {
        try {
            $count     = 0
            $scanStart = Get-Date
            "$evtLog`: starting..." | Set-Content $statusFile

            Get-WinEvent -FilterHashtable @{ LogName = $evtLog; StartTime = $logSince } `
                -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {
                $count++
                if ($count % 100 -eq 0) {
                    $secs = [math]::Max(1, [int]((Get-Date) - $scanStart).TotalSeconds)
                    $rate = [int]($count / $secs)
                    "$evtLog`: $count events (~${rate}/sec)" | Set-Content $statusFile
                }
                # Select fields directly -- Message excluded (slow DLL lookup, large output)
                [PSCustomObject]@{
                    TimeCreated      = $_.TimeCreated
                    Id               = $_.Id
                    Level            = $_.LevelDisplayName
                    Provider         = $_.ProviderName
                    TaskDisplayName  = $_.TaskDisplayName
                }
            } | Export-Csv "$out\10_eventlog_$evtLog.csv" -NoTypeInformation -Append -Encoding UTF8

            "$evtLog`: $count events collected" | Set-Content $statusFile
        } catch {
            "$evtLog`: no events or access denied" | Set-Content $statusFile
        }
    }

    # High-value event ID summary -- two queries (Security + System), group by Id
    # Much faster than one query per event ID against a large log.
    "Building high-value summary..." | Set-Content $statusFile
    $highValueIds = @(
        @{Id=4697; Log="Security"; Desc="Service installed"},
        @{Id=7045; Log="System";   Desc="New service created (System)"},
        @{Id=4698; Log="Security"; Desc="Scheduled task created"},
        @{Id=4702; Log="Security"; Desc="Scheduled task updated"},
        @{Id=1102; Log="Security"; Desc="AUDIT LOG CLEARED (!)"},
        @{Id=4688; Log="Security"; Desc="Process created"},
        @{Id=4657; Log="Security"; Desc="Registry value modified"},
        @{Id=4663; Log="Security"; Desc="Object access attempt"}
    )
    $secIds = @($highValueIds | Where-Object { $_.Log -eq "Security" } | ForEach-Object { $_.Id })
    $sysIds = @($highValueIds | Where-Object { $_.Log -eq "System"   } | ForEach-Object { $_.Id })

    $hvCounts = @{}
    try {
        Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=$secIds; StartTime=$logSince } `
            -MaxEvents 10000 -ErrorAction Stop |
            Group-Object Id | ForEach-Object { $hvCounts[[string]$_.Name] = $_.Count }
    } catch {}
    try {
        Get-WinEvent -FilterHashtable @{ LogName="System"; Id=$sysIds; StartTime=$logSince } `
            -MaxEvents 10000 -ErrorAction Stop |
            Group-Object Id | ForEach-Object { $hvCounts[[string]$_.Name] = $_.Count }
    } catch {}

    $lines = foreach ($ev in $highValueIds) {
        $c = if ($hvCounts.ContainsKey([string]$ev.Id)) { $hvCounts[[string]$ev.Id] } else { 0 }
        "$($ev.Id) | $($ev.Desc) | $c events in last 7 days"
    }
    $lines -join "`n" | Set-Content "$out\10_highvalue_event_summary.txt" -Encoding UTF8
    "Done" | Set-Content $statusFile

} -ArgumentList @($OutputPath, $logSince.ToFileTime(), $_evtStatusFile)

# --- File Share & Mapped Drives ----------------------------------------------

Start-Section "SHARES & MAPPED DRIVES" "SMB shares, mapped drives, open sessions and open files (CIS 3.3, 12.2 -- raw collection; ACL compliance analysis in CIS IG1 section below)"
Save "11_network_shares.txt"  (Get-SmbShare | Format-Table -AutoSize | Out-String)
Save "11_mapped_drives.txt"   (Get-PSDrive -PSProvider FileSystem | Format-Table -AutoSize | Out-String)
Save "11_open_sessions.txt"   (Get-SmbSession | Format-Table -AutoSize | Out-String)
Save "11_open_files.txt"      (Get-SmbOpenFile | Format-Table -AutoSize | Out-String)

# --- Hosts File & DNS ---------------------------------------------------------

Start-Section "HOSTS FILE / DNS TAMPERING" "Hosts file content and DNS client config -- check for redirect/hijack"
CopyFile "$env:SystemRoot\System32\drivers\etc\hosts" "12_hosts_file.txt"
Save "12_dns_client_config.txt" (Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String)

# --- Registry Persistence Checks ----------------------------------------------

Start-Section "REGISTRY PERSISTENCE" "Winlogon, BootExecute, IFEO, BHO -- less obvious but common persistence keys"
$persistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
)
$regOutput = foreach ($k in $persistenceKeys) {
    if (Test-Path $k) {
        "`n[$k]`n"
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Out-String
    }
}
Save "13_registry_persistence.txt" ($regOutput -join "")

# --- Prefetch Files -----------------------------------------------------------
# Prefetch shows every executable that has been launched on the machine.
# Critical forensic artifact -- shows programs that were run even if later deleted.

Start-Section "PREFETCH FILES" "C:\\Windows\\Prefetch -- shows every executable ever launched on this machine"

$prefetchDir = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchDir) {
    $pfFiles = Get-ChildItem $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
        Select-Object Name,
            @{N="SizeKB";E={[math]::Round($_.Length/1KB,1)}},
            CreationTime, LastWriteTime, LastAccessTime |
        Sort-Object LastWriteTime -Descending
    if ($pfFiles) {
        $pfFiles | Export-Csv "$OutputPath\13b_prefetch_files.csv" -NoTypeInformation
        Log "  $($pfFiles.Count) Prefetch files found -- see 13b_prefetch_files.csv"

        # Flag prefetch entries for known suspicious tools
        $suspPrefetch = $pfFiles | Where-Object {
            $_.Name -imatch "ANYDESK|TEAMVIEWER|SCREENCONNECT|PSEXEC|MIMIKATZ|RCLONE|NGROK|PLINK|WINSCP|FILEZILLA|PUTTY|NMAP|WIRESHARK|PROCDUMP|METERPRETER|COBALTSTRIKE|LAZAGNE|RUBEUS|CERTUTIL"
        }
        if ($suspPrefetch) {
            $suspPrefetch | Export-Csv "$OutputPath\13b_prefetch_FLAGGED.csv" -NoTypeInformation
            Log "  *** $($suspPrefetch.Count) suspicious Prefetch entries -- see 13b_prefetch_FLAGGED.csv ***" "DarkYellow"
            $suspPrefetch | ForEach-Object { Log "    $($_.Name) (last run: $($_.LastWriteTime))" "DarkYellow" }
        }
    } else {
        Log "  No Prefetch files found (Prefetch may be disabled)" "DarkGray"
    }
} else {
    Log "  Prefetch directory not found" "DarkGray"
}

# --- WMI Event Subscription Persistence ----------------------------------------
# WMI event subscriptions are a stealthy persistence mechanism. Malware and
# attackers use __EventFilter + __EventConsumer + __FilterToConsumerBinding
# to execute code on triggers (e.g., at logon, on a timer) without visible
# scheduled tasks or registry entries.

Start-Section "WMI PERSISTENCE" "WMI event subscriptions -- stealthy persistence mechanism used by advanced threats"

$wmiReport = @()
try {
    $filters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction Stop
    $consumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction Stop
    $bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction Stop

    foreach ($f in $filters) {
        $wmiReport += [PSCustomObject]@{
            Type  = "EventFilter"
            Name  = $f.Name
            Query = $f.Query
            Lang  = $f.QueryLanguage
        }
    }
    foreach ($c in $consumers) {
        $wmiReport += [PSCustomObject]@{
            Type  = "EventConsumer"
            Name  = $c.Name
            Query = if ($c.CommandLineTemplate) { $c.CommandLineTemplate }
                    elseif ($c.ScriptText) { $c.ScriptText.Substring(0, [Math]::Min($c.ScriptText.Length, 500)) }
                    else { $c.__CLASS }
            Lang  = $c.__CLASS
        }
    }
    foreach ($b in $bindings) {
        $wmiReport += [PSCustomObject]@{
            Type  = "FilterToConsumerBinding"
            Name  = "$($b.Filter) -> $($b.Consumer)"
            Query = ""
            Lang  = ""
        }
    }

    if ($wmiReport.Count -gt 0) {
        $wmiReport | Export-Csv "$OutputPath\13c_wmi_persistence.csv" -NoTypeInformation
        Log "  *** $($wmiReport.Count) WMI event subscription object(s) found -- review 13c_wmi_persistence.csv ***" "DarkYellow"
        $wmiReport | Where-Object { $_.Type -eq "EventConsumer" } | ForEach-Object {
            Log "    Consumer: $($_.Name) -- $($_.Query)" "DarkYellow"
        }
    } else {
        Log "  No WMI event subscriptions found (clean)" "DarkGray"
    }
} catch {
    Log "  Could not query WMI subscriptions: $_" "DarkGray"
}

# --- PowerShell Execution Policy ----------------------------------------------
$execPolicy = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue
Save "13d_ps_execution_policy.txt" ($execPolicy | Format-Table -AutoSize | Out-String)

# --- Webcam Investigation -----------------------------------------------------
#
# Focused on answering: what activated the webcam, when, and what software is
# responsible? Covers the Windows Camera Consent Store (the most reliable source),
# installed devices, Logitech-specific services, and browser site permissions.
# NO video frames or stream data are captured.

Start-Section "WEBCAM INVESTIGATION" "Camera access history, app permissions, Logitech services, browser site permissions"

# -- Installed camera / imaging devices (PnP) ------------------------------
# Include FriendlyName filter: Logitech webcams often enumerate as "Image" class
# with model-specific names (C920, C922, Brio) rather than "Camera" class.
$cameras = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
    $_.Class -imatch "^(Camera|Image)$" -or
    $_.FriendlyName -imatch "camera|webcam|logitech|brio|c920|c922|c925|c930|c1000|streamcam"
} | Select-Object FriendlyName, Status, Class, InstanceId, Manufacturer
Save "14_webcam_devices.txt" ($cameras | Format-Table -AutoSize | Out-String)
if (-not $cameras) {
    Log "  No camera PnP devices found by class or FriendlyName" "DarkYellow"
}

# -- Driver information for camera/imaging devices -------------------------
$cameraDrivers = Get-WmiObject Win32_PnPSignedDriver |
    Where-Object { $_.DeviceClass -imatch "^(Camera|Image)$" } |
    Select-Object DeviceName, DriverVersion, DriverDate, InfName, IsSigned, Signer
Save "14_webcam_drivers.txt" ($cameraDrivers | Format-Table -AutoSize | Out-String)

# -- Windows Camera Consent Store -- authoritative record of camera access --
# Available on Windows 10 1903+. Each app that has touched the camera gets an
# entry with LastUsedTimeStart / LastUsedTimeStop stored as Windows FILETIME.
# NonPackaged = classic Win32 apps; other subkeys = UWP / packaged apps.

$consentRoots = @(
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Hive = "CurrentUser"  },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Hive = "LocalMachine" }
)

$cameraAccessLog = foreach ($root in $consentRoots) {
    if (-not (Test-Path $root.Path)) { continue }
    Get-ChildItem $root.Path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($null -ne $props.LastUsedTimeStart -and $props.LastUsedTimeStart -ne 0) {
            [PSCustomObject]@{
                Hive       = $root.Hive
                App        = $_.PSChildName
                Permission = $props.Value
                LastStart  = [DateTime]::FromFileTime($props.LastUsedTimeStart)
                LastStop   = if ($props.LastUsedTimeStop -and $props.LastUsedTimeStop -ne 0) {
                                 [DateTime]::FromFileTime($props.LastUsedTimeStop)
                             } else { "(still active / not recorded)" }
            }
        }
    }
}

if ($cameraAccessLog) {
    $cameraAccessLog | Sort-Object LastStart -Descending |
        Format-Table Hive, App, Permission, LastStart, LastStop -AutoSize |
        Out-String |
        Set-Content "$OutputPath\14_webcam_access_history.txt" -Encoding UTF8
    Log "  Camera access history saved -- $(($cameraAccessLog).Count) entries" "Yellow"

    # Flag any access by non-obvious apps (not Teams/Zoom/Windows Camera/Logitech)
    $expectedApps = @("teams","zoom","skype","slack","discord","WindowsCamera","lghub","logitech","hello","facetime","webex","whatsapp","telegram","obs")
    $unexpectedAccess = $cameraAccessLog | Where-Object {
        $app = $_.App
        -not ($expectedApps | Where-Object { $app -imatch $_ })
    }
    if ($unexpectedAccess) {
        $unexpectedAccess | Sort-Object LastStart -Descending |
            Format-Table -AutoSize | Out-String |
            Set-Content "$OutputPath\14_webcam_access_UNEXPECTED.txt" -Encoding UTF8
        Log "  *** Unexpected apps accessed camera -- see 14_webcam_access_UNEXPECTED.txt ***" "DarkYellow"
        $script:indicators.WebcamUnexpectedAppCount = ($unexpectedAccess | Measure-Object).Count
    }
} else {
    Save "14_webcam_access_history.txt" "No camera access history found in Consent Store (Windows 10 1903+ required)."
    Log "  No consent store history found -- may need to check Windows version or audit policy" "DarkYellow"
}

# All apps that have a camera permission entry (whether or not they've used it)
$allCameraPerms = foreach ($root in $consentRoots) {
    if (-not (Test-Path $root.Path)) { continue }
    Get-ChildItem $root.Path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($props.Value) {
            [PSCustomObject]@{
                Hive       = $root.Hive
                App        = $_.PSChildName
                Permission = $props.Value
            }
        }
    }
}
Save "14_webcam_permissions_all.txt" ($allCameraPerms | Sort-Object Permission, App | Format-Table -AutoSize | Out-String)

# -- Windows Hello face sign-in (a common innocent cause of camera activation) -
$helloEnabled = $false
try {
    $helloFace = Get-WmiObject -Namespace "root\WMI" -Class "WinBio_Identity" -ErrorAction Stop
    $helloEnabled = $true
} catch {}
$helloReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider" -ErrorAction SilentlyContinue
$helloFaceReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio" -ErrorAction SilentlyContinue
@"
Windows Hello Face Sign-in
===========================
WinBio Credential Provider : $(if ($helloReg) { $helloReg | Out-String } else { "Key not found" })
WinBio Settings            : $(if ($helloFaceReg) { $helloFaceReg | Out-String } else { "Key not found" })

NOTE: Even if Hello Face appears disabled, the background enrollment check can
still briefly activate the camera indicator light on lock screen display.
"@ | Set-Content "$OutputPath\14_windows_hello_face.txt" -Encoding UTF8
Log "  Saved: 14_windows_hello_face.txt"

# -- Currently running processes that commonly use a webcam -----------------
$webcamRelatedNames = @(
    # Conferencing
    "Teams","ms-teams","Zoom","Skype","CiscoWebex","webex","slack","discord","Lync","WhatsApp","telegram",
    # Streaming / recording
    "obs64","obs32","obs","streamlabs","xsplit","ManyCam","SplitCam","camtasia","Snagit","ShareX","ScreenToGif",
    # Logitech
    "LGHUB","LogiOptions","LogiOptionsMgr","LogiTune","LogiCapture","lvcomsx","LvPrcSrv",
    "LogiRegistryService","lcore","lbt","LogiOverlay",
    # Windows built-in
    "WindowsCamera","WinCamera","SnippingTool",
    # Remote access (camera can be streamed via these)
    "anydesk","teamviewer","vncviewer","tvn","radmin","mstsc","rustdesk","splashtop",
    # Browsers (can hold camera via WebRTC -- note the tab, not the process, holds permission)
    "chrome","msedge","firefox","brave","opera"
)

$runningWebcamProcs = Get-Process | Where-Object {
    $pname = $_.Name
    $webcamRelatedNames | Where-Object { $pname -imatch "^$_$" }
} | Select-Object Id, Name, CPU,
    @{N="SizeMB";E={[math]::Round($_.WorkingSet/1MB,1)}},
    Path, StartTime,
    @{N="User";E={ try{(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}catch{"?"} }}

Save "14_webcam_related_processes.txt" ($runningWebcamProcs | Format-Table -AutoSize | Out-String)
if ($runningWebcamProcs) {
    Log "  Running webcam-capable processes: $($runningWebcamProcs.Name -join ', ')" "Yellow"
    $script:indicators.WebcamRelatedProcesses = @($runningWebcamProcs.Name | Select-Object -Unique)
}

# -- Browser camera site permissions (from Preferences JSON -- no sqlite needed) -
foreach ($profile in $profiles) {
    $user = $profile.Name
    $browserPrefs = @(
        @{ Path = "$($profile.FullName)\AppData\Local\Google\Chrome\User Data\Default\Preferences"; Label = "Chrome" },
        @{ Path = "$($profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Preferences";  Label = "Edge"   }
    )
    foreach ($bp in $browserPrefs) {
        if (-not (Test-Path $bp.Path)) { continue }
        try {
            $prefs = Get-Content $bp.Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $camPerms = $prefs.profile.content_settings.exceptions.media_stream_camera
            if ($camPerms) {
                $outFile = "$OutputPath\user_${user}\14_$($bp.Label)_camera_site_permissions.txt"
                @"
$($bp.Label) sites with saved camera permissions for user: $user
================================================================
"@ | Set-Content $outFile -Encoding UTF8
                $camPerms.PSObject.Properties | ForEach-Object {
                    "$($_.Name) => $($_.Value.last_modified | ForEach-Object { try { [DateTime]::FromFileTime([long]$_ * 10) } catch { $_ } })" +
                    "  setting=$($_.Value.setting)"
                } | Add-Content $outFile -Encoding UTF8
                Log "  $($bp.Label) camera site permissions saved for $user" "Yellow"
            }
        } catch {
            Log "  Could not parse $($bp.Label) Preferences for $user" "DarkGray"
        }
    }
}

# -- Logitech software, services, and registry ------------------------------
$logitechServices = Get-WmiObject Win32_Service |
    Where-Object { $_.Name -imatch "logi|logitech" -or $_.DisplayName -imatch "logi|logitech" } |
    Select-Object Name, DisplayName, State, StartMode, PathName
Save "14_logitech_services.txt" ($logitechServices | Format-Table -AutoSize | Out-String)

# Re-use $installed from section 08 if it exists, otherwise query again
if (-not $installed) {
    $installed = @(
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    ) | Where-Object { $_.DisplayName }
}
$logitechInstalled = $installed | Where-Object { $_.DisplayName -imatch "logi|logitech" }
Save "14_logitech_installed.txt" ($logitechInstalled | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String)

# Logitech registry keys -- may reveal configured devices, firmware, update settings
$logiRegPaths = @(
    "HKLM:\SOFTWARE\Logitech",
    "HKLM:\SOFTWARE\WOW6432Node\Logitech",
    "HKCU:\SOFTWARE\Logitech"
)
$logiReg = foreach ($lp in $logiRegPaths) {
    if (Test-Path $lp) {
        "`n[$lp]`n"
        Get-ChildItem $lp -Recurse -ErrorAction SilentlyContinue |
            Select-Object PSPath | Out-String
    }
}
Save "14_logitech_registry_keys.txt" ($logiReg -join "")

# -- WMI video capture device enumeration ----------------------------------
$videoDevices = Get-WmiObject Win32_PnPEntity |
    Where-Object {
        $_.PNPClass -imatch "^(Camera|Image)$" -or
        $_.Description -imatch "webcam|camera|video capture|usb video"
    } |
    Select-Object Name, Description, Status, DeviceID, PNPClass, Manufacturer
Save "14_video_capture_devices_wmi.txt" ($videoDevices | Format-Table -AutoSize | Out-String)

# -- Webcam investigation summary note -------------------------------------
@"
WEBCAM INVESTIGATION -- ANALYST NOTES
======================================
The Logitech "green light" activating randomly has several common benign causes:

  1. Windows Hello face recognition -- runs on lock screen or fast user switch.
     Check: 14_windows_hello_face.txt

  2. Logitech G HUB / Options / Tune -- periodically polls connected devices
     for firmware checks and telemetry. This is the most common cause.
     Check: 14_logitech_services.txt, 14_logitech_installed.txt

  3. Browser WebRTC -- a tab with an active camera permission (e.g., a web app
     left open) can hold the device open intermittently.
     Check: 14_*_camera_site_permissions.txt

  4. Video conferencing apps (Teams, Zoom, Slack) -- run background device
     enumeration even when not in a call to pre-warm the camera pipeline.
     Check: 14_webcam_related_processes.txt

  5. Malicious -- a RAT or spyware capturing video frames.
     Indicators: camera access by an unfamiliar process name in
     14_webcam_access_UNEXPECTED.txt, combined with external network connections.

PRIMARY EVIDENCE SOURCE: 14_webcam_access_history.txt
  The Windows Consent Store timestamps are the most reliable way to correlate
  "when did the light come on" with "what process triggered it."
  Cross-reference LastStart times against user-reported sightings.
"@ | Set-Content "$OutputPath\14_webcam_ANALYST_NOTES.txt" -Encoding UTF8
Log "  Saved: 14_webcam_ANALYST_NOTES.txt"

End-Section   # close the final (WEBCAM INVESTIGATION) section

# --- CIS IG1 Section 15: Account Hygiene (CIS 5.1, 5.2, 5.3, 5.4) ------------

Start-Section "CIS IG1 - ACCOUNT HYGIENE" "Dormant accounts, password policy, privilege review (CIS 5.1-5.4)"

$ninetyDaysAgo = (Get-Date).AddDays(-90)

# Full local account inventory
$allLocalUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
    PasswordNeverExpires, PasswordRequired, UserMayChangePassword, Description |
    Sort-Object Name
$allLocalUsers | Export-Csv "$OutputPath\15_cis_accounts_all.csv" -NoTypeInformation
Log "  [CIS 5.1] $($allLocalUsers.Count) local accounts inventoried"

# Dormant: enabled accounts with no logon in 90+ days, or never logged in
$dormant = $allLocalUsers | Where-Object {
    $_.Enabled -eq $true -and (
        ($_.LastLogon -eq $null) -or ($_.LastLogon -lt $ninetyDaysAgo)
    )
}
if ($dormant) {
    $dormant | Export-Csv "$OutputPath\15_cis_dormant_FLAGGED.csv" -NoTypeInformation
    $script:cisIG1.DormantAccounts = @($dormant.Name)
    Log "  [CIS 5.3] *** FLAGGED: $($dormant.Count) dormant/unused enabled accounts ***" "DarkYellow"
    $dormant | ForEach-Object {
        $lastLogonStr = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd") } else { "NEVER" }
        Log "    $($_.Name) -- last logon: $lastLogonStr" "DarkYellow"
    }
} else {
    Log "  [CIS 5.3] No dormant enabled accounts found" "DarkGray"
}

# Never logged in (subset of dormant -- worth calling out specifically)
$neverIn = $allLocalUsers | Where-Object { $_.Enabled -and $_.LastLogon -eq $null }
if ($neverIn) {
    $script:cisIG1.NeverLoggedInAccounts = @($neverIn.Name)
    Log "  [CIS 5.3] $($neverIn.Count) enabled account(s) have never been used" "DarkYellow"
}

# Password never expires
$pwdNoExpire = $allLocalUsers | Where-Object { $_.Enabled -and $_.PasswordNeverExpires }
if ($pwdNoExpire) {
    $pwdNoExpire | Export-Csv "$OutputPath\15_cis_password_noexpire_FLAGGED.csv" -NoTypeInformation
    $script:cisIG1.PasswordNeverExpires = @($pwdNoExpire.Name)
    Log "  [CIS 5.2] *** FLAGGED: $($pwdNoExpire.Count) enabled accounts with password never expires ***" "DarkYellow"
} else {
    Log "  [CIS 5.2] No accounts with non-expiring passwords" "DarkGray"
}

# Privileged group membership
$privGroups = @("Administrators","Remote Desktop Users","Power Users","Backup Operators")
$privReport = @()
foreach ($grp in $privGroups) {
    try {
        $members = Get-LocalGroupMember -Group $grp -ErrorAction Stop
        $members | ForEach-Object {
            $privReport += [PSCustomObject]@{
                Group          = $grp
                Name           = $_.Name
                PrincipalSource = $_.PrincipalSource
                ObjectClass    = $_.ObjectClass
            }
        }
    } catch {}
}
if ($privReport) {
    $privReport | Export-Csv "$OutputPath\15_cis_privileged_group_members.csv" -NoTypeInformation
    $adminMembers = @($privReport | Where-Object { $_.Group -eq "Administrators" })
    $script:cisIG1.PrivilegedAccounts = @($adminMembers.Name)
    Log "  [CIS 5.4] Administrators group members: $($adminMembers.Count)"
    $adminMembers | ForEach-Object { Log "    $($_.Name) ($($_.PrincipalSource))" "Gray" }
}

# Local password policy (net accounts)
$pwPolicy = & net accounts 2>&1
Save "15_cis_password_policy.txt" ($pwPolicy | Out-String)
Log "  [CIS 5.2] Local password policy saved to 15_cis_password_policy.txt"

# CIS 4.7 -- Default account hardening
# Built-in Administrator = RID 500; Guest = RID 501
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID.ToString().EndsWith("-500") }
$builtinGuest = Get-LocalUser | Where-Object { $_.SID.ToString().EndsWith("-501") }

if ($builtinAdmin) {
    $script:cisIG1.DefaultAdminRenamed = ($builtinAdmin.Name -ne "Administrator")
    $script:cisIG1.DefaultAdminEnabled = $builtinAdmin.Enabled
    if ($builtinAdmin.Name -eq "Administrator") {
        Log "  [CIS 4.7] *** FLAGGED: Built-in Administrator account still uses default name ***" "DarkYellow"
    } else {
        Log "  [CIS 4.7] Built-in Administrator renamed to: $($builtinAdmin.Name)" "DarkGray"
    }
    if ($builtinAdmin.Enabled) {
        Log "  [CIS 4.7] *** FLAGGED: Built-in Administrator account is enabled ***" "DarkYellow"
    } else {
        Log "  [CIS 4.7] Built-in Administrator is disabled" "DarkGray"
    }
}
if ($builtinGuest) {
    $script:cisIG1.GuestEnabled = $builtinGuest.Enabled
    if ($builtinGuest.Enabled) {
        Log "  [CIS 4.7] *** FLAGGED: Guest account is enabled ***" "DarkYellow"
    } else {
        Log "  [CIS 4.7] Guest account is disabled" "DarkGray"
    }
}

# --- CIS IG1 Section 16: Patch & Update Status (CIS 7.3, 7.4) ----------------

Start-Section "CIS IG1 - PATCH STATUS" "Installed hotfixes, pending updates, OS build age (CIS 7.3-7.4)"

# Installed hotfixes
$allHotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
$allHotfixes | Export-Csv "$OutputPath\16_cis_installed_hotfixes.csv" -NoTypeInformation
Log "  [CIS 7.3] $($allHotfixes.Count) hotfixes/patches in history"

$lastPatch = $allHotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
if ($lastPatch) {
    $daysSince = [int]((Get-Date) - $lastPatch.InstalledOn).TotalDays
    $script:cisIG1.DaysSinceLastPatch = $daysSince
    $script:cisIG1.LastPatchKB = $lastPatch.HotFixID
    if ($daysSince -gt 30) {
        Log "  [CIS 7.3] *** FLAGGED: Last patch was $daysSince days ago ($($lastPatch.HotFixID)) ***" "DarkYellow"
    } else {
        Log "  [CIS 7.3] Last patch: $daysSince days ago ($($lastPatch.HotFixID))" "Gray"
    }
} else {
    Log "  [CIS 7.3] *** FLAGGED: No patch install dates found -- patching may be unmanaged ***" "DarkYellow"
}

# OS build info for EOL check
$osInfo = Get-WmiObject Win32_OperatingSystem
$buildStr = "$($osInfo.Caption)  Build $($osInfo.BuildNumber)  Version $($osInfo.Version)"
$script:cisIG1.WindowsBuild = $buildStr
Log "  [CIS 7.4] $buildStr"

# Check for known EOL Windows 10 builds (feature update versions)
$buildNum = [int]$osInfo.BuildNumber
$win10EolBuilds = @(10240,10586,14393,15063,16299,17134,17763,18362,18363,19041,19042,19043)
if ($osInfo.Caption -match "Windows 10" -and $buildNum -in $win10EolBuilds) {
    Log "  [CIS 7.4] *** FLAGGED: Windows 10 Build $buildNum is end-of-life and no longer receives security updates ***" "DarkYellow"
} elseif ($osInfo.Caption -match "Windows 7|Windows 8|Server 2008|Server 2012") {
    Log "  [CIS 7.4] *** FLAGGED: $($osInfo.Caption) is end-of-life ***" "Red"
}

# Pending updates via WUA COM object (skippable)
$_patchStatusFile = "$env:TEMP\ce_patch_status.tmp"
Invoke-Skippable -Label "pending Windows updates check (WUA)" -StatusFile $_patchStatusFile -Action {
    param($out, $statusFile)
    try {
        "Connecting to Windows Update Agent..." | Set-Content $statusFile
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
        $count    = $result.Updates.Count
        "$count pending updates found" | Set-Content $statusFile
        if ($count -gt 0) {
            $pending = 0..($count - 1) | ForEach-Object {
                $u = $result.Updates.Item($_)
                [PSCustomObject]@{
                    Title    = $u.Title
                    Severity = $u.MsrcSeverity
                    KB       = ($u.KBArticleIDs -join ",")
                }
            }
            $pending | Export-Csv "$out\16_cis_pending_updates_FLAGGED.csv" -NoTypeInformation
        } else {
            "No pending updates found" | Set-Content "$out\16_cis_pending_updates.txt"
        }
        "Pending updates: $count" | Set-Content $statusFile
    } catch {
        "WUA query error: $_" | Set-Content "$out\16_cis_pending_updates_error.txt"
    }
} -ArgumentList @($OutputPath, $_patchStatusFile)

# Read pending count into indicators if file was created
$pendingFile = "$OutputPath\16_cis_pending_updates_FLAGGED.csv"
if (Test-Path $pendingFile) {
    $pendingCount = (Import-Csv $pendingFile | Measure-Object).Count
    $script:cisIG1.PendingUpdatesCount = $pendingCount
    Log "  [CIS 7.3] *** FLAGGED: $pendingCount pending update(s) found ***" "DarkYellow"
} else {
    $script:cisIG1.PendingUpdatesCount = 0
}

# CIS 9.1 -- Browser version EOL check
# Captures installed versions; flags major versions below known-safe minimums.
# Update $minVersions when new major releases supersede these.
$minVersions = @{ Chrome = 120; Edge = 120; Firefox = 120 }
$browserVersions = @{}

$chromePath = "HKLM:\SOFTWARE\Google\Chrome\BLBeacon"
if (Test-Path $chromePath) {
    $v = (Get-ItemProperty $chromePath -ErrorAction SilentlyContinue).version
    if ($v) {
        $browserVersions["Chrome"] = $v
        $major = [int]($v -split "\.")[0]
        if ($major -lt $minVersions.Chrome) {
            Log "  [CIS 9.1] *** FLAGGED: Chrome $v is outdated (min recommended major: $($minVersions.Chrome)) ***" "DarkYellow"
        } else { Log "  [CIS 9.1] Chrome $v -- current" "DarkGray" }
    }
}

$edgePath = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
if (-not (Test-Path $edgePath)) {
    $edgePath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
}
if (Test-Path $edgePath) {
    $v = (Get-ItemProperty $edgePath -ErrorAction SilentlyContinue).pv
    if ($v -and $v -ne "0.0.0.0") {
        $browserVersions["Edge"] = $v
        $major = [int]($v -split "\.")[0]
        if ($major -lt $minVersions.Edge) {
            Log "  [CIS 9.1] *** FLAGGED: Edge $v is outdated (min recommended major: $($minVersions.Edge)) ***" "DarkYellow"
        } else { Log "  [CIS 9.1] Edge $v -- current" "DarkGray" }
    }
}

$ffPath = "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox"
if (Test-Path $ffPath) {
    $v = (Get-ItemProperty $ffPath -ErrorAction SilentlyContinue).CurrentVersion
    if ($v) {
        $browserVersions["Firefox"] = $v
        $major = [int]($v -split "\.")[0]
        if ($major -lt $minVersions.Firefox) {
            Log "  [CIS 9.1] *** FLAGGED: Firefox $v is outdated (min recommended major: $($minVersions.Firefox)) ***" "DarkYellow"
        } else { Log "  [CIS 9.1] Firefox $v -- current" "DarkGray" }
    }
}
$script:cisIG1.BrowserVersions = $browserVersions
if ($browserVersions.Count -eq 0) { Log "  [CIS 9.1] No tracked browsers detected" "DarkGray" }

# CIS 8.4 -- NTP / time synchronization
$w32Status = & w32tm /query /status 2>&1
$w32Config = & w32tm /query /configuration 2>&1
"=== w32tm /query /status ===`n$($w32Status -join "`n")`n`n=== w32tm /query /configuration ===`n$($w32Config -join "`n")" |
    Set-Content "$OutputPath\16_cis_ntp_status.txt" -Encoding UTF8
$sourceLine = $w32Status | Where-Object { $_ -match "^Source\s*:" } | Select-Object -First 1
$ntpSource = if ($sourceLine) { ($sourceLine -split ":",2)[1].Trim() } else { "unknown" }
$script:cisIG1.NTPSource = $ntpSource
if ($ntpSource -match "Local CMOS|Free-running|VM IC") {
    $script:cisIG1.NTPSynced = $false
    Log "  [CIS 8.4] *** FLAGGED: NTP source is '$ntpSource' -- not syncing to external time source ***" "DarkYellow"
} else {
    $script:cisIG1.NTPSynced = $true
    Log "  [CIS 8.4] NTP source: $ntpSource" "DarkGray"
}

Start-Section "CIS IG1 - NETWORK SHARES" "SMB share inventory and overpermissive ACLs (CIS 3.3, 12.2)"

try {
    $allShares = Get-SmbShare -ErrorAction Stop
    $script:cisIG1.AllShareNames = @($allShares.Name)
    Log "  [CIS 12.2] $($allShares.Count) SMB share(s) found: $($allShares.Name -join ', ')"

    $shareReport = @()
    foreach ($share in $allShares) {
        try {
            $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop
            $acl | ForEach-Object {
                $shareReport += [PSCustomObject]@{
                    ShareName   = $share.Name
                    Path        = $share.Path
                    Description = $share.Description
                    Account     = $_.AccountName
                    AccessType  = $_.AccessControlType
                    Permission  = $_.AccessRight
                }
            }
        } catch {
            $shareReport += [PSCustomObject]@{
                ShareName = $share.Name; Path = $share.Path
                Description = $share.Description; Account = "(ACL read error)"
                AccessType = ""; Permission = ""
            }
        }
    }
    $shareReport | Export-Csv "$OutputPath\17_cis_shares_all.csv" -NoTypeInformation

    # Flag overpermissive: Everyone or Users with Full or Change rights on non-admin shares
    $openACEs = $shareReport | Where-Object {
        $_.Account  -match "Everyone|Authenticated Users|BUILTIN\\Users" -and
        $_.Permission -match "Full|Change" -and
        $_.ShareName -notmatch "^(ADMIN\$|IPC\$|print\$)$"
    }
    if ($openACEs) {
        $openACEs | Export-Csv "$OutputPath\17_cis_shares_OVERPERMISSIVE_FLAGGED.csv" -NoTypeInformation
        $script:cisIG1.OpenShareCount = ($openACEs | Select-Object ShareName -Unique | Measure-Object).Count
        Log "  [CIS 3.3] *** FLAGGED: $($script:cisIG1.OpenShareCount) share(s) with broad public access ***" "DarkYellow"
        $openACEs | ForEach-Object { Log "    \\$hostname\$($_.ShareName)  ->  $($_.Account) : $($_.Permission)" "DarkYellow" }
    } else {
        Log "  [CIS 3.3] No overpermissive share ACLs found" "DarkGray"
    }
} catch {
    Log "  Get-SmbShare: $_  (SMB cmdlets may require elevated session or Server feature)" "DarkGray"
}

# Sensitive user folder ACLs -- catch cases where profiles are world-readable
$folderAclReport = @()
foreach ($profile in $profiles) {
    foreach ($subPath in @("Desktop","Documents","Downloads")) {
        $fp = Join-Path $profile.FullName $subPath
        if (-not (Test-Path $fp)) { continue }
        try {
            $acl = Get-Acl $fp
            $acl.Access | Where-Object {
                $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users"
            } | ForEach-Object {
                $folderAclReport += [PSCustomObject]@{
                    User       = $profile.Name
                    Path       = $fp
                    Identity   = $_.IdentityReference
                    Rights     = $_.FileSystemRights
                    AccessType = $_.AccessControlType
                    Inherited  = $_.IsInherited
                }
            }
        } catch {}
    }
}
if ($folderAclReport) {
    $folderAclReport | Export-Csv "$OutputPath\17_cis_folder_broad_access.csv" -NoTypeInformation
    Log "  [CIS 3.3] $($folderAclReport.Count) broad-access ACE(s) on user profile folders -- see 17_cis_folder_broad_access.csv" "DarkYellow"
} else {
    Log "  [CIS 3.3] User profile folders have normal ACLs" "DarkGray"
}

# CIS 3.6 -- BitLocker / drive encryption status
$blReport = @()
try {
    $vols = Get-WmiObject -Namespace "root\cimv2\security\microsoftvolumeencryption" `
        -Class Win32_EncryptableVolume -ErrorAction Stop
    foreach ($vol in $vols) {
        $statusText = switch ($vol.ProtectionStatus) {
            0 { "NOT ENCRYPTED" }
            1 { "Encrypted (Protected)" }
            2 { "Encryption Unknown" }
            default { "Status $($vol.ProtectionStatus)" }
        }
        $blReport += [PSCustomObject]@{
            Drive  = $vol.DriveLetter
            Status = $statusText
        }
        if ($vol.ProtectionStatus -ne 1) {
            Log "  [CIS 3.6] *** FLAGGED: Drive $($vol.DriveLetter) is $statusText ***" "DarkYellow"
        } else {
            Log "  [CIS 3.6] Drive $($vol.DriveLetter): $statusText" "DarkGray"
        }
    }
} catch {
    # WMI namespace not available -- fall back to manage-bde
    $bdeOut = & manage-bde -status 2>&1
    $blReport += [PSCustomObject]@{ Drive = "ALL"; Status = ($bdeOut -join " ") }
    Log "  [CIS 3.6] manage-bde fallback used -- see 17_cis_bitlocker_status.csv" "DarkGray"
}
$blReport | Export-Csv "$OutputPath\17_cis_bitlocker_status.csv" -NoTypeInformation
$script:cisIG1.BitLockerStatus = @($blReport | ForEach-Object { "$($_.Drive): $($_.Status)" })

# CIS 10.3 -- Autorun / AutoPlay disabled for removable media
$autorunKey  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$autorunVal  = (Get-ItemProperty $autorunKey -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
# Bit 4 (0x4) = removable drives; 0xFF = all drives; Microsoft recommendation = 0xFF
if ($autorunVal -ne $null) {
    $removableDisabled = ($autorunVal -band 0x4) -ne 0
    $script:cisIG1.AutorunDisabled = $removableDisabled
    if ($removableDisabled) {
        Log "  [CIS 10.3] Autorun disabled for removable drives (NoDriveTypeAutoRun = 0x$('{0:X}' -f $autorunVal))" "DarkGray"
    } else {
        Log "  [CIS 10.3] *** FLAGGED: Autorun not explicitly disabled for removable drives ***" "DarkYellow"
    }
} else {
    $script:cisIG1.AutorunDisabled = $false
    Log "  [CIS 10.3] *** FLAGGED: NoDriveTypeAutoRun not set -- autorun policy not configured ***" "DarkYellow"
}

End-Section   # close CIS shares/encryption section

# --- CIS IG1 - SECURE CONFIGURATION ------------------------------------------

Start-Section "CIS IG1 - SECURE CONFIGURATION" "SMBv1, LLMNR, screen lock, audit logging, PowerShell logging (CIS 4.1, 4.3, 8.3, 8.5)"

# CIS 4.1 -- SMBv1 protocol (major attack vector -- WannaCry, EternalBlue)
$smb1Enabled = $null
try {
    # Server-side SMBv1
    $smb1Server = Get-SmbServerConfiguration -ErrorAction Stop
    $smb1Enabled = $smb1Server.EnableSMB1Protocol
} catch {
    # Fallback: check the Windows Feature / registry
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        $smb1Enabled = ($smb1Feature.State -eq "Enabled")
    } catch {
        $smb1Reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
        if ($smb1Reg.PSObject.Properties.Name -contains "SMB1") {
            $smb1Enabled = ($smb1Reg.SMB1 -ne 0)
        }
    }
}
$script:cisIG1.SMBv1Enabled = $smb1Enabled
if ($smb1Enabled -eq $true) {
    Log "  [CIS 4.1] *** FLAGGED: SMBv1 protocol is ENABLED -- vulnerable to EternalBlue/WannaCry ***" "DarkYellow"
} elseif ($smb1Enabled -eq $false) {
    Log "  [CIS 4.1] SMBv1 disabled" "DarkGray"
} else {
    Log "  [CIS 4.1] SMBv1 status could not be determined" "DarkGray"
}

# CIS 4.1 -- LLMNR disabled (prevents LLMNR poisoning / credential relay)
$llmnrKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrVal = (Get-ItemProperty $llmnrKey -ErrorAction SilentlyContinue).EnableMulticast
# EnableMulticast = 0 means LLMNR is disabled (secure)
if ($llmnrVal -eq 0) {
    $script:cisIG1.LLMNRDisabled = $true
    Log "  [CIS 4.1] LLMNR disabled via policy" "DarkGray"
} else {
    $script:cisIG1.LLMNRDisabled = $false
    Log "  [CIS 4.1] *** FLAGGED: LLMNR is enabled -- vulnerable to name resolution poisoning ***" "DarkYellow"
}

# CIS 4.1 -- NetBIOS over TCP/IP (another name resolution poisoning vector)
$nbDisabled = $true
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
foreach ($adapter in $adapters) {
    # TcpipNetbiosOptions: 0=Default (DHCP), 1=Enabled, 2=Disabled
    if ($adapter.TcpipNetbiosOptions -ne 2) {
        $nbDisabled = $false
    }
}
$script:cisIG1.NetBIOSDisabled = $nbDisabled
if ($nbDisabled) {
    Log "  [CIS 4.1] NetBIOS over TCP/IP disabled on all adapters" "DarkGray"
} else {
    Log "  [CIS 4.1] *** FLAGGED: NetBIOS over TCP/IP enabled on one or more adapters -- poisoning risk ***" "DarkYellow"
}

$secConfigReport = [ordered]@{
    SMBv1Enabled   = $smb1Enabled
    LLMNRDisabled  = $script:cisIG1.LLMNRDisabled
    NetBIOSDisabled = $nbDisabled
}
$secConfigReport | ConvertTo-Json | Set-Content "$OutputPath\18_cis_secure_config.json" -Encoding UTF8

# CIS 4.3 -- Automatic session locking (screen lock timeout)
$screenLockTimeout = $null
$screenLockSecure  = $null

# Check Group Policy inactivity timeout first (takes precedence)
$inactivityKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$inactivityTimeout = (Get-ItemProperty $inactivityKey -ErrorAction SilentlyContinue).InactivityTimeoutSecs
if ($inactivityTimeout) {
    $screenLockTimeout = $inactivityTimeout
}

# Check per-user screensaver settings
$ssTimeout = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
$ssSecure  = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue).ScreenSaverIsSecure

if (-not $screenLockTimeout -and $ssTimeout) {
    $screenLockTimeout = [int]$ssTimeout
}
$screenLockSecure = ($ssSecure -eq "1") -or ($inactivityTimeout -and $inactivityTimeout -gt 0)

$script:cisIG1.ScreenLockTimeout = $screenLockTimeout
$script:cisIG1.ScreenLockEnabled = $screenLockSecure

if (-not $screenLockTimeout -or $screenLockTimeout -eq 0) {
    Log "  [CIS 4.3] *** FLAGGED: No automatic screen lock timeout configured ***" "DarkYellow"
} elseif ($screenLockTimeout -gt 900) {
    Log "  [CIS 4.3] *** FLAGGED: Screen lock timeout is $screenLockTimeout seconds ($([math]::Round($screenLockTimeout/60,0)) min) -- recommended max is 15 min ***" "DarkYellow"
} else {
    Log "  [CIS 4.3] Screen lock timeout: $screenLockTimeout seconds ($([math]::Round($screenLockTimeout/60,0)) min)" "DarkGray"
}
if (-not $screenLockSecure) {
    Log "  [CIS 4.3] *** FLAGGED: Screen saver does not require password on resume ***" "DarkYellow"
}

[ordered]@{
    InactivityTimeoutSecs  = $inactivityTimeout
    ScreenSaverTimeout     = $ssTimeout
    ScreenSaverIsSecure    = $ssSecure
    EffectiveTimeoutSecs   = $screenLockTimeout
    PasswordRequired       = $screenLockSecure
} | ConvertTo-Json | Set-Content "$OutputPath\18_cis_screen_lock.json" -Encoding UTF8

# CIS 8.3 -- Adequate audit log storage (check max log sizes)
$logSizes = @{}
foreach ($evtLogName in @("Security","System","Application","Windows PowerShell")) {
    try {
        $logObj = Get-WinEvent -ListLog $evtLogName -ErrorAction Stop
        $maxMB  = [math]::Round($logObj.MaximumSizeInBytes / 1MB, 1)
        $usedMB = [math]::Round($logObj.FileSize / 1MB, 1)
        $logSizes[$evtLogName] = [ordered]@{
            MaxSizeMB  = $maxMB
            UsedMB     = $usedMB
            RecordCount = $logObj.RecordCount
            Retention  = $logObj.LogMode
        }
        if ($maxMB -lt 64 -and $evtLogName -eq "Security") {
            Log "  [CIS 8.3] *** FLAGGED: Security log max size is only ${maxMB}MB (recommend 256MB+) ***" "DarkYellow"
        } elseif ($maxMB -lt 32) {
            Log "  [CIS 8.3] *** FLAGGED: $evtLogName log max size is only ${maxMB}MB ***" "DarkYellow"
        } else {
            Log "  [CIS 8.3] $evtLogName log: ${usedMB}MB / ${maxMB}MB ($($logObj.RecordCount) records, $($logObj.LogMode))" "DarkGray"
        }
    } catch {
        Log "  [CIS 8.3] Could not query $evtLogName log size: $_" "DarkGray"
    }
}
$script:cisIG1.AuditLogMaxSizes = $logSizes
$logSizes | ConvertTo-Json -Depth 3 | Set-Content "$OutputPath\18_cis_audit_log_sizes.json" -Encoding UTF8

# CIS 8.5 -- Detailed audit logging: PowerShell ScriptBlock and Module logging
$psLogging = [ordered]@{}
$sblKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sblEnabled = (Get-ItemProperty $sblKey -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$psLogging.ScriptBlockLogging = ($sblEnabled -eq 1)
$script:cisIG1.PSScriptBlockLogging = ($sblEnabled -eq 1)

$mlKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$mlEnabled = (Get-ItemProperty $mlKey -ErrorAction SilentlyContinue).EnableModuleLogging
$psLogging.ModuleLogging = ($mlEnabled -eq 1)
$script:cisIG1.PSModuleLogging = ($mlEnabled -eq 1)

# Also check transcription
$trKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$trEnabled = (Get-ItemProperty $trKey -ErrorAction SilentlyContinue).EnableTranscripting
$trDir = (Get-ItemProperty $trKey -ErrorAction SilentlyContinue).OutputDirectory
$psLogging.Transcription = ($trEnabled -eq 1)
$psLogging.TranscriptionDir = $trDir

$psLogging | ConvertTo-Json | Set-Content "$OutputPath\18_cis_ps_logging.json" -Encoding UTF8

if ($sblEnabled -ne 1) {
    Log "  [CIS 8.5] *** FLAGGED: PowerShell Script Block Logging not enabled ***" "DarkYellow"
} else {
    Log "  [CIS 8.5] PowerShell Script Block Logging enabled" "DarkGray"
}
if ($mlEnabled -ne 1) {
    Log "  [CIS 8.5] *** FLAGGED: PowerShell Module Logging not enabled ***" "DarkYellow"
} else {
    Log "  [CIS 8.5] PowerShell Module Logging enabled" "DarkGray"
}
if ($trEnabled -eq 1) {
    Log "  [CIS 8.5] PowerShell Transcription enabled (output: $trDir)" "DarkGray"
} else {
    Log "  [CIS 8.5] PowerShell Transcription not enabled" "DarkGray"
}

End-Section   # close CIS secure configuration section

# --- Summary JSON Files -------------------------------------------------------

$script:indicators | ConvertTo-Json -Depth 5 |
    Set-Content "$OutputPath\quick_indicators.json" -Encoding UTF8
Log "  Saved: quick_indicators.json"

[ordered]@{
    BrowserKeywordHitCount   = $script:indicators.BrowserKeywordHitCount
    BrowserKeywordHitDomains = $script:indicators.BrowserKeywordHitDomains
    WebcamUnexpectedAppCount = $script:indicators.WebcamUnexpectedAppCount
    WebcamRelatedProcesses   = $script:indicators.WebcamRelatedProcesses
    RDPEnabled               = $script:indicators.RDPEnabled
    VirtualAdaptersFound     = $script:indicators.VirtualAdaptersFound
    ExternalConnectionCount  = $script:indicators.ExternalConnectionCount
} | ConvertTo-Json -Depth 5 |
    Set-Content "$OutputPath\webcam_concern_summary.json" -Encoding UTF8
Log "  Saved: webcam_concern_summary.json"

$script:cisIG1 | ConvertTo-Json -Depth 5 |
    Set-Content "$OutputPath\cis_ig1_gaps.json" -Encoding UTF8
Log "  Saved: cis_ig1_gaps.json"

# --- CIS IG1 Section 18: Network Discovery and Remote Recon ------------------
# Only runs when -NetworkScan switch is specified.
# Requires admin rights on remote machines (current user or -RemoteCredential).
# Usage:
#   .\Collect-Evidence.ps1 -NetworkScan
#   .\Collect-Evidence.ps1 -NetworkScan -Subnet "10.0.1"
#   .\Collect-Evidence.ps1 -NetworkScan -RemoteCredential (Get-Credential)

if ($NetworkScan) {
    Start-Section "NETWORK DISCOVERY" "Subnet ping sweep and remote WMI recon of all live hosts"

    # Auto-detect subnet from first non-loopback IPv4 adapter
    if (-not $Subnet) {
        $localAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPEnabled -and $_.IPAddress -and
                ($_.IPAddress | Where-Object { $_ -notmatch "^169\.|^127\." }) } |
            Select-Object -First 1
        if ($localAdapter) {
            $localIP = $localAdapter.IPAddress |
                Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" } | Select-Object -First 1
            $Subnet  = ($localIP -split "\.")[0..2] -join "."
            Log "  Auto-detected local IP: $localIP  Scanning subnet: $Subnet.0/24"
        } else {
            Log "  Could not auto-detect subnet. Use -Subnet '192.168.1' to specify." "DarkYellow"
        }
    }

    if ($Subnet) {
        $netOut = "$OutputPath\network_scan"
        New-Item -ItemType Directory -Path $netOut -Force | Out-Null

        # ── Parallel ping sweep via runspace pool (50 concurrent) ────────────
        Log "  Starting parallel ping sweep of $Subnet.0/24 ..."
        $sweepStart = Get-Date

        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 50)
        $pool.Open()

        $pingJobs = 1..254 | ForEach-Object {
            $ip = "$Subnet.$_"
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            $ps.AddScript({
                param($addr, $ms)
                $p = New-Object System.Net.NetworkInformation.Ping
                try {
                    $r = $p.Send($addr, $ms)
                    [PSCustomObject]@{ IP = $addr; Alive = ($r.Status -eq "Success") }
                } catch {
                    [PSCustomObject]@{ IP = $addr; Alive = $false }
                }
            }).AddArgument($ip).AddArgument($PingTimeout) | Out-Null
            [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip }
        }

        $liveHosts = @()
        foreach ($j in $pingJobs) {
            $res = $j.PS.EndInvoke($j.Handle)
            if ($res -and $res.Alive) { $liveHosts += $res.IP }
            $j.PS.Dispose()
        }
        $pool.Close()
        $pool.Dispose()

        $sweepSec = [math]::Round(((Get-Date) - $sweepStart).TotalSeconds, 1)
        Log "  Ping sweep complete in ${sweepSec}s -- $($liveHosts.Count) live host(s): $($liveHosts -join ', ')"

        # ── WMI recon per live host ───────────────────────────────────────────
        $suspiciousKeywordsNet = @(
            "anydesk","teamviewer","screenconnect","logmein","ammyy","netsupport",
            "vnc","radmin","ngrok","frp","plink","wireshark","mimikatz","procdump",
            "rclone","psexec","meterpreter","cobalt"
        )

        $networkSummary = @()

        foreach ($ip in $liveHosts) {
            Log "  Probing $ip ..."
            $wmiArgs = @{ ComputerName = $ip; ErrorAction = "SilentlyContinue" }
            if ($RemoteCredential) { $wmiArgs.Credential = $RemoteCredential }

            $machineOut = [ordered]@{
                IP               = $ip
                Hostname         = ""
                OS               = ""
                LastBoot         = ""
                Domain           = ""
                RDPEnabled       = "unknown"
                FirewallDisabled = "unknown"
                AVProduct        = ""
                LocalAdminCount  = 0
                SuspiciousProcs  = @()
                SuspiciousSvcs   = @()
                SMBAccessible    = $false
                Flags            = ""
                Errors           = @()
            }

            # DNS hostname
            try {
                $dns = [System.Net.Dns]::GetHostEntry($ip)
                $machineOut.Hostname = $dns.HostName
            } catch { $machineOut.Hostname = "(no DNS)" }

            $label   = if ($machineOut.Hostname -and $machineOut.Hostname -ne "(no DNS)") {
                ($machineOut.Hostname -replace "\..+$","") -replace "[^a-zA-Z0-9_-]","_"
            } else { $ip -replace "\.","_" }
            $machDir = "$netOut\$label"
            New-Item -ItemType Directory -Path $machDir -Force | Out-Null

            # OS and domain
            try {
                $os  = Get-WmiObject Win32_OperatingSystem @wmiArgs
                $cs  = Get-WmiObject Win32_ComputerSystem  @wmiArgs
                if ($os) {
                    $machineOut.OS       = "$($os.Caption) Build $($os.BuildNumber)"
                    $machineOut.LastBoot = $os.ConvertToDateTime($os.LastBootUpTime).ToString("yyyy-MM-dd HH:mm")
                    $machineOut.Domain   = $cs.Domain
                    $os | Select-Object Caption, BuildNumber, Version, LastBootUpTime |
                        Export-Csv "$machDir\os_info.csv" -NoTypeInformation
                }
            } catch { $machineOut.Errors += "OS: $($_.Exception.Message)" }

            # Local users
            try {
                $users = Get-WmiObject Win32_UserAccount @wmiArgs -Filter "LocalAccount=True"
                $users | Select-Object Name, Disabled, Lockout, PasswordExpires, Description |
                    Export-Csv "$machDir\local_users.csv" -NoTypeInformation
            } catch { $machineOut.Errors += "Users: $($_.Exception.Message)" }

            # Admin group membership
            try {
                $admins = Get-WmiObject Win32_GroupUser @wmiArgs |
                    Where-Object { $_.GroupComponent -match 'Name="Administrators"' } |
                    ForEach-Object {
                        if ($_.PartComponent -match 'Name="([^"]+)"') { $Matches[1] }
                    }
                $machineOut.LocalAdminCount = @($admins).Count
                ($admins | Out-String).Trim() | Set-Content "$machDir\admin_members.txt" -Encoding UTF8
            } catch { $machineOut.Errors += "Admins: $($_.Exception.Message)" }

            # Running processes -- flag suspicious
            try {
                $procs = Get-WmiObject Win32_Process @wmiArgs |
                    Select-Object Name, ProcessId, ExecutablePath, CommandLine
                $procs | Export-Csv "$machDir\processes.csv" -NoTypeInformation

                $flaggedProcs = $procs | Where-Object {
                    $n = $_.Name.ToLower()
                    $suspiciousKeywordsNet | Where-Object { $n -match $_ }
                }
                if ($flaggedProcs) {
                    $flaggedProcs | Export-Csv "$machDir\processes_FLAGGED.csv" -NoTypeInformation
                    $machineOut.SuspiciousProcs = @($flaggedProcs.Name)
                    Log "    *** SUSPICIOUS PROCESSES on ${ip}: $($flaggedProcs.Name -join ', ') ***" "DarkYellow"
                }
            } catch { $machineOut.Errors += "Procs: $($_.Exception.Message)" }

            # Running services -- flag non-standard paths
            try {
                $svcs = Get-WmiObject Win32_Service @wmiArgs |
                    Where-Object { $_.State -eq "Running" } |
                    Select-Object Name, DisplayName, State, PathName, StartName
                $svcs | Export-Csv "$machDir\services_running.csv" -NoTypeInformation

                $weirdSvcs = $svcs | Where-Object {
                    $_.PathName -and
                    $_.PathName -notmatch 'System32|SysWOW64|Program Files|svchost|Windows' -and
                    $_.PathName -notmatch '^"?[A-Z]:\\Windows'
                }
                if ($weirdSvcs) {
                    $weirdSvcs | Export-Csv "$machDir\services_SUSPICIOUS.csv" -NoTypeInformation
                    $machineOut.SuspiciousSvcs = @($weirdSvcs.Name)
                }
            } catch { $machineOut.Errors += "Services: $($_.Exception.Message)" }

            # RDP and firewall status via remote registry
            try {
                $reg   = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ip)
                $tsKey = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Terminal Server")
                if ($tsKey) {
                    $machineOut.RDPEnabled = ($tsKey.GetValue("fDenyTSConnections") -eq 0)
                }
                $fwKey = $reg.OpenSubKey(
                    "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy")
                if ($fwKey) {
                    $disabled = @()
                    foreach ($profile in @("StandardProfile","PublicProfile","DomainProfile")) {
                        $pk = $fwKey.OpenSubKey($profile)
                        if ($pk -and $pk.GetValue("EnableFirewall") -eq 0) { $disabled += $profile }
                    }
                    $machineOut.FirewallDisabled = if ($disabled) { $disabled -join "," } else { "No" }
                }
                $reg.Close()
            } catch { $machineOut.Errors += "RemoteReg: $($_.Exception.Message)" }

            # AV product
            try {
                $av = Get-WmiObject -Namespace "root\SecurityCenter2" @wmiArgs -Class AntiVirusProduct
                if ($av) { $machineOut.AVProduct = ($av.displayName) -join "; " }
            } catch { $machineOut.Errors += "AV: $($_.Exception.Message)" }

            # SMB admin share check
            try {
                $machineOut.SMBAccessible = (Test-Path "\\$ip\C$" -ErrorAction SilentlyContinue)
            } catch {}

            # Installed software -- only if SMB/WMI fully accessible (Win32_Product is slow; skip if errors above)
            if ($machineOut.SMBAccessible -and $machineOut.Errors.Count -eq 0) {
                try {
                    $sw = Get-WmiObject Win32_Product @wmiArgs |
                        Select-Object Name, Version, Vendor, InstallDate
                    $sw | Export-Csv "$machDir\installed_software.csv" -NoTypeInformation
                    $remoteTools = $sw | Where-Object {
                        $_.Name -imatch "anydesk|teamviewer|screenconnect|filezilla|winscp|vnc|radmin|idrive"
                    }
                    if ($remoteTools) {
                        $remoteTools | Export-Csv "$machDir\remote_tools_FLAGGED.csv" -NoTypeInformation
                        Log "    *** REMOTE TOOLS on ${ip}: $($remoteTools.Name -join ', ') ***" "DarkYellow"
                    }
                } catch { $machineOut.Errors += "Software: $($_.Exception.Message)" }
            }

            # Summarize flags
            $flags = @()
            if ($machineOut.RDPEnabled -eq $true) { $flags += "RDP-ON" }
            if ($machineOut.FirewallDisabled -and
                $machineOut.FirewallDisabled -notin @("No","unknown")) {
                $flags += "FW-OFF"
            }
            if ($machineOut.SuspiciousProcs.Count -gt 0) { $flags += "SUSP-PROCS" }
            if ($machineOut.SuspiciousSvcs.Count  -gt 0) { $flags += "SUSP-SVCS" }
            $machineOut.Flags = $flags -join " | "

            $machineOut | ConvertTo-Json -Depth 3 |
                Set-Content "$machDir\machine_summary.json" -Encoding UTF8

            $networkSummary += [PSCustomObject]@{
                IP               = $machineOut.IP
                Hostname         = $machineOut.Hostname
                OS               = $machineOut.OS
                LastBoot         = $machineOut.LastBoot
                Domain           = $machineOut.Domain
                RDPEnabled       = $machineOut.RDPEnabled
                FirewallDisabled = $machineOut.FirewallDisabled
                AVProduct        = $machineOut.AVProduct
                LocalAdminCount  = $machineOut.LocalAdminCount
                SuspiciousProcs  = $machineOut.SuspiciousProcs -join "; "
                SMBAccessible    = $machineOut.SMBAccessible
                Flags            = $machineOut.Flags
            }

            if ($flags) {
                Log "    $ip ($($machineOut.Hostname)) -- FLAGS: $($machineOut.Flags)" "DarkYellow"
            } else {
                Log "    $ip ($($machineOut.Hostname)) -- clean" "DarkGray"
            }
        }

        # Network-wide summary CSV
        $networkSummary | Export-Csv "$netOut\network_summary.csv" -NoTypeInformation
        Log "  Network summary: $netOut\network_summary.csv"

        $redFlags = $networkSummary | Where-Object { $_.Flags }
        if ($redFlags) {
            Log "  *** $($redFlags.Count) machine(s) flagged for review ***" "DarkYellow"
            $redFlags | ForEach-Object { Log "    $($_.IP) ($($_.Hostname)) -- $($_.Flags)" "DarkYellow" }
        }
    }

    End-Section
}

# --- Wrap Up ------------------------------------------------------------------

$totalElapsed = [math]::Round(((Get-Date) - $script:_scriptStart).TotalSeconds)
$summary = @"

================================================
  Evidence Collection Complete
  Host      : $hostname
  Time      : $(Get-Date)
  Elapsed   : ${totalElapsed}s
  Output    : $OutputPath
================================================
NEXT STEPS:
  1. Review quick_indicators.json for an instant risk summary.
  2. Review cis_ig1_gaps.json for CIS IG1 compliance gaps.
  3. START HERE for webcam: 14_webcam_ANALYST_NOTES.txt
       then: 14_webcam_access_history.txt  (who used camera and when)
       then: 14_webcam_access_UNEXPECTED.txt  (if it exists -- red flag)
       then: 09b_browser_keyword_FLAGGED.csv  (what were they researching?)
  4. CIS IG1 gap files:
       15_cis_dormant_FLAGGED.csv, 16_cis_pending_updates_FLAGGED.csv,
       17_cis_shares_OVERPERMISSIVE_FLAGGED.csv, 17_cis_bitlocker_status.csv,
       18_cis_secure_config.json, 18_cis_screen_lock.json,
       18_cis_audit_log_sizes.json, 18_cis_ps_logging.json
  5. Forensic persistence: 13b_prefetch_FLAGGED.csv, 13c_wmi_persistence.csv
  6. Security: 07_defender_exclusions.json (attacker abuse check)
  7. Open .db files in "DB Browser for SQLite" (https://sqlitebrowser.org)
  8. Open .csv event logs in Excel or Timeline Explorer
  9. Review all files marked _FLAGGED, _SUSPICIOUS, or _UNEXPECTED first.
  10. If criminal activity found, stop -- preserve and contact law enforcement
      BEFORE making any additional system changes.
================================================
"@
Write-Host $summary -ForegroundColor Green
Add-Content -Path $logFile -Value $summary

# --- Auto-ZIP Evidence Folder -------------------------------------------------

$zipPath = "$OutputPath.zip"
Log "  Compressing evidence folder to $zipPath ..."
try {
    Compress-Archive -Path $OutputPath -DestinationPath $zipPath -Force -ErrorAction Stop
    $zipSizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Log "  Evidence archive ready: $zipPath (${zipSizeMB}MB)" "Green"
} catch {
    Log "  Could not create ZIP: $_" "DarkYellow"
}
