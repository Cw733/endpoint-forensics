# endpoint-forensics

Windows endpoint forensics and security audit toolkit for small-to-medium environments.

## Contents

| File | Description |
|------|-------------|
| `Collect-Evidence.ps1` | Comprehensive endpoint evidence collector. Gathers system info, logon events, processes, services, scheduled tasks, network state, browser history (no cookies/credentials), USB history, webcam access logs, and CIS IG1 compliance gaps. Run as Administrator. |
| `Analysis-Prompt.txt` | AI analysis prompt for use with GitHub Copilot CLI or any capable AI assistant. Feed this file to the AI along with your evidence folder path to generate a standardized security audit or investigation report. |
| `CIS-IG1-Manual-Checklist.txt` | CIS Controls Implementation Group 1 manual assessment checklist for items requiring interviews, document review, or access to non-endpoint systems (identity provider, firewall, backup platform). |
| `FortiGate-Export-Checklist.txt` | On-site Fortinet FortiGate export checklist. Covers configuration backup, event logs, traffic logs, security logs, firewall policy review, VPN configuration, admin accounts, and log retention. |
| `commands.txt` | Quick-reference commands for running the collection scripts. |

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

# Both
.\Collect-Evidence.ps1 -TargetUser "jsmith" -OutputRoot "E:\Audits"
```

### Analyzing Results

1. Open a new GitHub Copilot CLI session
2. Feed it `Analysis-Prompt.txt` as context
3. Say: `"I have an evidence folder from Collect-Evidence.ps1 at [path]. Generate a security audit report."`
4. For an investigation report: `"Also generate an investigation findings report for user [username]."`

Browser history `.db` files (SQLite) can be opened with [DB Browser for SQLite](https://sqlitebrowser.org).

### FortiGate Audit

Use `FortiGate-Export-Checklist.txt` when conducting an on-site Fortinet firewall review. Pair exports with `Analysis-Prompt.txt` for AI-assisted log analysis.

### CIS IG1 Assessment

Run `Collect-Evidence.ps1` first — it covers all technical/measurable CIS IG1 safeguards automatically. Then work through `CIS-IG1-Manual-Checklist.txt` with the site owner or IT contact for the items requiring human review.

## Legal Notice

> Only run these tools on systems you are **explicitly authorized** to investigate.  
> Obtain **written authorization** from the asset owner before use.  
> Preserve chain of custody — document who ran what, when, and keep original copies untouched.  
> If criminal activity is found, **stop and contact law enforcement** before making any system changes.