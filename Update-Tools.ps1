<#
.SYNOPSIS
    Downloads and updates portable forensics tools used by Collect.ps1.

.DESCRIPTION
    Run this script on an internet-connected machine to download or update:
      - Sysinternals Suite (autorunsc, sigcheck, listdlls, accesschk, streams)
      - Chainsaw (Sigma-based Windows event log scanner)
      - hayabusa (fast Windows event log threat hunter)
      - WinPmem (RAM acquisition)

    Tools are saved to a .\tools\ folder relative to this script.
    Collect.ps1 auto-detects tools in ..\tools\ when run from the repo folder,
    so the intended USB layout is:

        USB:\
        ├── tools\          ← created/updated by this script
        ├── Collect.ps1
        ├── Update-Tools.ps1
        └── Analysis-Prompt.txt

.PARAMETER ToolsPath
    Override the destination folder. Default: .\tools (relative to script).

.PARAMETER SkipSysinternals
    Skip the Sysinternals Suite download.

.PARAMETER SkipChainsaw
    Skip the Chainsaw download.

.PARAMETER SkipHayabusa
    Skip the hayabusa download.

.PARAMETER SkipWinPmem
    Skip the WinPmem download.

.EXAMPLE
    .\Update-Tools.ps1
    Downloads/updates all tools to .\tools\

.EXAMPLE
    .\Update-Tools.ps1 -ToolsPath D:\USB\tools
    Downloads tools to a specific path.

.EXAMPLE
    .\Update-Tools.ps1 -SkipSysinternals
    Update everything except Sysinternals.

.NOTES
    Author : Casey Wilkins / Knextion
    Repo   : https://github.com/Cw733/endpoint-forensics
    Requires: Internet access, PowerShell 5.1+
    No admin rights required (just writing to the tools folder).
#>

param(
    [string]$ToolsPath = "$PSScriptRoot\tools",
    [switch]$SkipSysinternals,
    [switch]$SkipChainsaw,
    [switch]$SkipHayabusa,
    [switch]$SkipWinPmem
)

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "  $Message" -ForegroundColor $Color
}

function Download-GitHubRelease {
    <#
    .SYNOPSIS
        Downloads the latest release asset from a GitHub repo.
    #>
    param(
        [string]$Repo,          # e.g. "WithSecureLabs/chainsaw"
        [string]$AssetPattern,  # regex to match the asset filename
        [string]$DestDir,       # folder to extract/save into
        [string]$ToolName,      # display name
        [switch]$IsExe          # if true, asset is a standalone .exe (not a zip)
    )

    Write-Host "`n[$ToolName]" -ForegroundColor White
    try {
        $headers = @{ "User-Agent" = "Update-Tools/1.0" }
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers $headers -ErrorAction Stop
        $asset = $release.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
        if (-not $asset) {
            Write-Status "No matching asset for pattern: $AssetPattern" "Yellow"
            Write-Status "Available assets: $($release.assets.name -join ', ')" "DarkGray"
            return $false
        }

        # Check if we already have this version
        $versionFile = "$DestDir\.version"
        $currentVersion = if (Test-Path $versionFile) { Get-Content $versionFile -Raw } else { "" }
        if ($currentVersion.Trim() -eq $release.tag_name) {
            Write-Status "Already up to date ($($release.tag_name))" "Green"
            return $true
        }

        if (-not (Test-Path $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }

        $dlFile = "$env:TEMP\$($asset.name)"
        Write-Status "Downloading $($asset.name) ($([math]::Round($asset.size/1MB,1)) MB)..."
        Invoke-WebRequest $asset.browser_download_url -OutFile $dlFile -Headers $headers -ErrorAction Stop

        if ($IsExe) {
            Copy-Item $dlFile "$DestDir\$($asset.name)" -Force
        } else {
            Write-Status "Extracting to $DestDir..."
            Expand-Archive $dlFile -DestinationPath $DestDir -Force
        }

        Remove-Item $dlFile -Force -ErrorAction SilentlyContinue
        $release.tag_name | Set-Content $versionFile -Force
        Write-Status "Updated to $($release.tag_name)" "Green"
        return $true
    } catch {
        Write-Status "FAILED: $_" "Red"
        return $false
    }
}

# ── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Update-Tools.ps1 — Portable Forensics Toolkit Updater" -ForegroundColor Cyan
Write-Host "  Destination: $ToolsPath" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

if (-not (Test-Path $ToolsPath)) {
    New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null
    Write-Status "Created tools directory: $ToolsPath" "Green"
}

$results = @{}

# ── 1. Sysinternals Suite ────────────────────────────────────────────────────

if (-not $SkipSysinternals) {
    Write-Host "`n[Sysinternals Suite]" -ForegroundColor White
    $sysDir = "$ToolsPath\sysinternals"
    if (-not (Test-Path $sysDir)) { New-Item -ItemType Directory -Path $sysDir -Force | Out-Null }

    # Try the live share first (fastest, always current)
    $liveShare = "\\live.sysinternals.com\tools"
    $neededTools = @("autorunsc64.exe","autorunsc.exe","sigcheck64.exe","sigcheck.exe",
                     "Listdlls64.exe","Listdlls.exe","accesschk64.exe","accesschk.exe",
                     "streams64.exe","streams.exe","handle64.exe","handle.exe",
                     "tcpview.exe","procexp64.exe","procexp.exe","procmon64.exe","procmon.exe")

    $liveOk = $false
    try {
        if (Test-Path $liveShare -ErrorAction Stop) {
            Write-Status "Copying from live.sysinternals.com..."
            $copied = 0
            foreach ($tool in $neededTools) {
                $src = "$liveShare\$tool"
                if (Test-Path $src) {
                    Copy-Item $src "$sysDir\$tool" -Force
                    $copied++
                }
            }
            Write-Status "$copied tools updated from live share" "Green"
            (Get-Date -Format "yyyy-MM-dd") | Set-Content "$sysDir\.version" -Force
            $liveOk = $true
        }
    } catch {}

    if (-not $liveOk) {
        # Fallback: download the full suite zip from Microsoft
        Write-Status "Live share unavailable — downloading SysinternalsSuite.zip..." "Yellow"
        try {
            $sysZip = "$env:TEMP\SysinternalsSuite.zip"
            Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" `
                -OutFile $sysZip -ErrorAction Stop
            Expand-Archive $sysZip -DestinationPath $sysDir -Force
            Remove-Item $sysZip -Force -ErrorAction SilentlyContinue
            (Get-Date -Format "yyyy-MM-dd") | Set-Content "$sysDir\.version" -Force
            Write-Status "Suite downloaded and extracted" "Green"
        } catch {
            Write-Status "FAILED: $_" "Red"
            $results["Sysinternals"] = "FAILED"
        }
    }
    if (-not $results.ContainsKey("Sysinternals")) { $results["Sysinternals"] = "OK" }

    # Verify the tools Collect.ps1 needs
    Write-Status "Verifying Collect.ps1 integration tools:" "DarkGray"
    $collectTools = @("autorunsc64.exe","sigcheck64.exe","Listdlls64.exe","accesschk64.exe","streams64.exe")
    foreach ($t in $collectTools) {
        $found = Test-Path "$sysDir\$t"
        $icon = if ($found) { "[OK]" } else { "[MISSING]" }
        $color = if ($found) { "Green" } else { "Red" }
        Write-Status "  $icon $t" $color
    }
} else {
    Write-Status "Skipped Sysinternals (--SkipSysinternals)" "DarkGray"
    $results["Sysinternals"] = "SKIPPED"
}

# ── 2. Chainsaw ──────────────────────────────────────────────────────────────

if (-not $SkipChainsaw) {
    $ok = Download-GitHubRelease `
        -Repo "WithSecureLabs/chainsaw" `
        -AssetPattern "chainsaw_x86_64-pc-windows-msvc\.zip$" `
        -DestDir "$ToolsPath\chainsaw" `
        -ToolName "Chainsaw"
    $results["Chainsaw"] = if ($ok) { "OK" } else { "FAILED" }
} else {
    $results["Chainsaw"] = "SKIPPED"
}

# ── 3. hayabusa ──────────────────────────────────────────────────────────────

if (-not $SkipHayabusa) {
    $ok = Download-GitHubRelease `
        -Repo "Yamato-Security/hayabusa" `
        -AssetPattern "hayabusa-.*-win-x64\.zip$" `
        -DestDir "$ToolsPath\hayabusa" `
        -ToolName "hayabusa"
    $results["hayabusa"] = if ($ok) { "OK" } else { "FAILED" }

    # Update hayabusa detection rules if binary exists
    $hayaExe = Get-ChildItem "$ToolsPath\hayabusa" -Filter "hayabusa*.exe" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch 'update' } | Select-Object -First 1
    if ($hayaExe) {
        Write-Status "Updating hayabusa detection rules..."
        try {
            & $hayaExe.FullName update-rules -q 2>&1 | Out-Null
            Write-Status "Rules updated" "Green"
        } catch {
            Write-Status "Rule update failed (non-critical): $_" "Yellow"
        }
    }
} else {
    $results["hayabusa"] = "SKIPPED"
}

# ── 4. WinPmem ──────────────────────────────────────────────────────────────

if (-not $SkipWinPmem) {
    $ok = Download-GitHubRelease `
        -Repo "Velocidex/WinPmem" `
        -AssetPattern "winpmem_mini.*\.exe$" `
        -DestDir "$ToolsPath\winpmem" `
        -ToolName "WinPmem" `
        -IsExe
    $results["WinPmem"] = if ($ok) { "OK" } else { "FAILED" }
} else {
    $results["WinPmem"] = "SKIPPED"
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  UPDATE SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

foreach ($tool in $results.GetEnumerator() | Sort-Object Name) {
    $color = switch ($tool.Value) {
        "OK"      { "Green" }
        "SKIPPED" { "DarkGray" }
        default   { "Red" }
    }
    Write-Host "  $($tool.Key): $($tool.Value)" -ForegroundColor $color
}

# Show total tools folder size
$totalSize = (Get-ChildItem $ToolsPath -Recurse -File -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum).Sum
Write-Host "`n  Tools folder size: $([math]::Round($totalSize/1MB,1)) MB" -ForegroundColor Cyan
Write-Host "  Location: $ToolsPath" -ForegroundColor Cyan
Write-Host ""

$failed = @($results.Values | Where-Object { $_ -eq "FAILED" })
if ($failed.Count -gt 0) {
    Write-Host "  $($failed.Count) tool(s) failed — check errors above and retry." -ForegroundColor Red
    exit 1
} else {
    Write-Host "  All tools ready. Run Collect.ps1 to use them." -ForegroundColor Green
    exit 0
}
