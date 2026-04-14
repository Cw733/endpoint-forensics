# endpoint-forensics

Windows endpoint forensics and security audit toolkit for small-to-medium environments.

## Contents

| File | Description |
|------|-------------|
| `Collect-Evidence.ps1` | Comprehensive endpoint evidence collector with CIS IG1 compliance checks. Gathers system info, logon events, processes, services, scheduled tasks, network state, Defender status/exclusions, browser history, USB history, Prefetch artifacts, WMI persistence, webcam access logs, and full CIS IG1 gap analysis. Outputs public IP for external scanning. Run as Administrator. |
| `Analysis-Prompt.txt` | AI analysis prompt for use with GitHub Copilot CLI or any capable AI assistant. Feed this file along with your evidence folder path to generate a standardized security audit report with CIS IG1 compliance table, or a user-specific investigation report. |
| `CIS-IG1-Manual-Checklist.txt` | CIS Controls IG1 manual assessment checklist for items requiring interviews, document review, or access to non-endpoint systems (identity provider, firewall, backup platform). |
| `FortiGate-Export-Checklist.txt` | On-site Fortinet FortiGate export checklist. Covers configuration backup, event logs, traffic logs, security logs, firewall policy review, VPN configuration, admin accounts, and log retention. |
| `commands.txt` | Quick-reference commands for running the collection scripts. |

## CIS IG1 Coverage

The script automatically checks the following CIS v8 IG1 safeguards at the endpoint level:

| CIS Control | Safeguards Checked |
|-------------|-------------------|
| 1.1 Asset Inventory | System info, OS, BIOS, public IP |
| 2.1 Software Inventory | All installed software with dates |
| 3.3 Data Access Controls | SMB share ACLs, user folder ACLs |
| 3.6 Encrypt End-User Devices | BitLocker / drive encryption status |
| 4.1 Secure Configuration | SMBv1, LLMNR, NetBIOS over TCP, firewall profiles, RDP |
| 4.3 Session Locking | Screen lock timeout, password-on-resume |
| 4.4/4.5 Host Firewall | Firewall profiles, broad inbound rules |
| 4.7 Default Account Mgmt | Admin/Guest account status, renamed check |
| 5.1-5.4 Account Management | Inventory, dormant, password policy, admin privileges |
| 7.3-7.4 Patch Management | Hotfix history, pending updates, OS EOL, browser versions |
| 8.2-8.5 Audit Logging | Log collection, log sizes/retention, NTP sync, PS ScriptBlock/Module logging |
| 9.1 Supported Browsers | Chrome, Edge, Firefox version checks |
| 10.1-10.4 Malware Defenses | Defender status, signatures, behavior monitor, exclusions, removable media scan, autorun |
| 12.2 Network Infrastructure | Share inventory, listening ports |

Items that require manual/organizational review are covered in `CIS-IG1-Manual-Checklist.txt`.

## Usage

### Evidence Collection

```powershell
# Run PowerShell as Administrator, then:
Set-ExecutionPolicy -Scope Process Bypass

# Collect from all users, output next to script
.\Collect-Evidence.ps1

# Target a specific user
.\Collect-Evidence.ps1 -TargetUser "jsmith"

# Specify output path (e.g., external drive)
.\Collect-Evidence.ps1 -OutputRoot "E:\Audits"

# Include network scan of all hosts on the LAN
.\Collect-Evidence.ps1 -NetworkScan

# Full options
.\Collect-Evidence.ps1 -TargetUser "jsmith" -OutputRoot "E:\Audits" -NetworkScan -Subnet "10.0.1" -RemoteCredential (Get-Credential)

# Show detailed help
.\Collect-Evidence.ps1 -Help
```

### Key Output Files

Start with these files for a rapid assessment:

| File | Purpose |
|------|---------|
| `quick_indicators.json` | Machine-generated risk flag summary (start here) |
| `cis_ig1_gaps.json` | All CIS IG1 automated compliance results |
| `07_defender_exclusions.json` | Defender exclusions (attacker abuse check) |
| `13b_prefetch_FLAGGED.csv` | Attack tools that were executed (if any) |
| `13c_wmi_persistence.csv` | Stealthy WMI persistence (if any) |
| `18_cis_secure_config.json` | SMBv1/LLMNR/NetBIOS status |

Review all files with `_FLAGGED`, `_SUSPICIOUS`, or `_UNEXPECTED` suffixes as priority items.

### Analyzing Results

1. Open a new GitHub Copilot CLI session
2. Feed it `Analysis-Prompt.txt` as context
3. Say: `"I have an evidence folder from Collect-Evidence.ps1 at [path]. Generate a security audit report following the instructions in the prompt file."`
4. For an investigation report: `"Also generate an investigation findings report for user [username]."`
5. The AI will generate a report with a full CIS IG1 compliance table aligned to CIS control numbers.

Browser history `.db` files (SQLite) can be opened with [DB Browser for SQLite](https://sqlitebrowser.org).

### FortiGate Audit

Use `FortiGate-Export-Checklist.txt` when conducting an on-site Fortinet firewall review. Pair exports with `Analysis-Prompt.txt` for AI-assisted log analysis.

### CIS IG1 Assessment

Run `Collect-Evidence.ps1` first -- it covers all technically measurable CIS IG1 safeguards at the endpoint level. Then work through `CIS-IG1-Manual-Checklist.txt` with the site owner or IT contact for items requiring human review (asset management process, MFA, backup verification, security awareness training, incident response plan).

## Legal Notice

> Only run these tools on systems you are **explicitly authorized** to investigate.
> Obtain **written authorization** from the asset owner before use.
> Preserve chain of custody -- document who ran what, when, and keep original copies untouched.
> If criminal activity is found, **stop and contact law enforcement** before making any system changes.
