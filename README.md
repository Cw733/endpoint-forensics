# endpoint-forensics

Windows endpoint forensics and security audit toolkit for small-to-medium environments.

## Contents

| File | Description |
|------|-------------|
| `Collect.ps1` | Comprehensive endpoint evidence collector with CIS IG1 compliance checks. Gathers system info, logon events, processes, services, scheduled tasks, network state, Defender status/exclusions, browser history, USB history, Prefetch artifacts, WMI persistence, webcam access logs, AmCache/ShimCache/SRUM/Shellbags/UserAssist/BAM execution artifacts, Windows Timeline, LNK metadata, browser extensions, VSS shadows, Recycle Bin metadata, RDP client history, EDR/Sysmon/WSL detection, kernel drivers, DoH/ETW config, and full CIS IG1 gap analysis. Outputs public IP for external scanning. Run as Administrator. |
| `convert-report.ps1` | Converts a markdown security assessment report to .docx. Runs Pandoc for the conversion, then applies Word COM post-processing: table borders, heading size/spacing/AllCaps, and gray italic disclaimer styling. Requires Pandoc and Microsoft Word. |
| `Parse-FortiGate.ps1` | Parses a FortiGate configuration backup (`.conf` file) into structured CSVs for firewall policy, address objects, service objects, admin accounts, VPN config, and log settings. Use alongside `FortiGate-Export-Checklist.txt`. |
| `Update-Tools.ps1` | Downloads and refreshes the optional external forensic tool bundle (WinPmem, Chainsaw + Sigma rules, Hayabusa, Sysinternals) into a local `tools\` directory for use with `-ToolsPath`, `-CaptureRAM`, and `-ThreatHunt`. Safe to re-run; idempotent. |
| `Analysis-Prompt.txt` | AI analysis prompt for use with GitHub Copilot CLI or any capable AI assistant. Feed this file along with your evidence folder path to generate three standardized deliverables: (1) a security audit report with CIS IG1 compliance table, (2) a citation verification table mapping every claim to its evidence source, and (3) a one-page non-technical executive summary for the business owner. Also supports user-specific investigation reports. Includes document generation instructions and formatting rules. |
| `CIS-IG1-Manual-Checklist.txt` | CIS Controls IG1 manual assessment checklist for items requiring interviews, document review, or access to non-endpoint systems (identity provider, firewall, backup platform). |
| `FortiGate-Export-Checklist.txt` | On-site Fortinet FortiGate export checklist. Covers configuration backup, event logs, traffic logs, security logs, firewall policy review, VPN configuration, admin accounts, and log retention. |
| `commands.txt` | Quick-reference commands for running the collection and conversion scripts. |

## Prerequisites

- **Windows** with PowerShell 5.1 or newer
- **Administrator access** on the target machine (for evidence collection)
- **Microsoft Word** installed (required for `convert-report.ps1` post-processing)
- **Pandoc** for .docx report generation:
  ```
  winget install --id JohnMacFarlane.Pandoc
  ```
  After installation, refresh PATH in the current PowerShell session before use:
  ```powershell
  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
  ```

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
.\Collect.ps1

# Target a specific user
.\Collect.ps1 -TargetUser "jsmith"

# Specify output path (e.g., external drive)
.\Collect.ps1 -OutputRoot "E:\Audits"

# Include network scan of all hosts on the LAN
.\Collect.ps1 -NetworkScan

# Full options
.\Collect.ps1 -TargetUser "jsmith" -OutputRoot "E:\Audits" -NetworkScan -Subnet "10.0.1" -RemoteCredential (Get-Credential)

# Show detailed help
.\Collect.ps1 -Help
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
| `20_AmCache.hve` + `20_ShimCache.reg` | Execution evidence (survives Prefetch wipe) |
| `20_SRUDB.dat` + `20_SOFTWARE.hive` | Per-app network bytes sent/received (30-60 days) |
| `20_Shellbags.reg` / `20_UserAssist.reg` / `20_BAM.reg` | Activity timeline artifacts |
| `20_drivers_UNSIGNED_FLAGGED.csv` | Unsigned kernel drivers (if any) |
| `20_EDR_detected.csv` | Third-party EDR/AV product detection |

Review all files with `_FLAGGED`, `_SUSPICIOUS`, or `_UNEXPECTED` suffixes as priority items.

### Analyzing Results

1. Open a new GitHub Copilot CLI session
2. Feed it `Analysis-Prompt.txt` as context
3. Say: `"I have an evidence folder from Collect.ps1 at [path]. Generate a security audit report following the instructions in the prompt file."`
4. For an investigation report: `"Also generate an investigation findings report for user [username]."`
5. The AI will read the evidence files and produce three deliverables:
   - **Main report** (`[Client]-CIS-IG1-Security-Assessment.md`) -- full technical findings with CIS IG1 compliance table
   - **Citation verification table** (`[Client]-Citation-Verification.md`) -- maps every factual claim to its evidence source
   - **Executive summary** (`[Client]-Executive-Summary.md`) -- one-page, non-technical summary suitable for the business owner or board; same citation standards as the main report

Browser history `.db` files (SQLite) can be opened with [DB Browser for SQLite](https://sqlitebrowser.org).

### Converting Reports to Word

After generating your markdown report, convert to .docx with `convert-report.ps1`:

```powershell
# Install Pandoc first (one-time):
winget install --id JohnMacFarlane.Pandoc

# Then convert (refresh PATH if needed first):
.\convert-report.ps1 -InputMd ".\report.md" -ReferenceDoc ".\reference-style.docx"

# With explicit output path:
.\convert-report.ps1 -InputMd ".\report.md" -ReferenceDoc ".\ref.docx" -OutputDocx ".\report-final.docx"
```

A **reference-style.docx** is required for consistent heading and body styles. Create one by
running Pandoc on a minimal markdown file, adjusting heading styles in Word, and saving it as
your style template. Store it alongside this toolkit.

The script applies these post-processing steps automatically:
- Table borders (inside and outside)
- Heading AllCaps + increased font size (H1: 22pt, H2: 16pt, H3: 13pt)
- Heading SpaceBefore/SpaceAfter for visual section separation
- Gray italic styling for blockquote/disclaimer text

### FortiGate Audit

Use `FortiGate-Export-Checklist.txt` when conducting an on-site Fortinet firewall review. Pair exports with `Analysis-Prompt.txt` for AI-assisted log analysis.

### CIS IG1 Assessment

Run `Collect.ps1` first -- it covers all technically measurable CIS IG1 safeguards at the endpoint level. Then work through `CIS-IG1-Manual-Checklist.txt` with the site owner or IT contact for items requiring human review (asset management process, MFA, backup verification, security awareness training, incident response plan).

## Legal Notice

> Only run these tools on systems you are **explicitly authorized** to investigate.
> Obtain **written authorization** from the asset owner before use.
> Preserve chain of custody -- document who ran what, when, and keep original copies untouched.
> If criminal activity is found, **stop and contact law enforcement** before making any system changes.