<#
.SYNOPSIS
    Converts a markdown security assessment report to .docx using Pandoc
    with Word COM post-processing for table borders and heading formatting.

.PARAMETER InputMd
    Path to the source markdown report file.

.PARAMETER OutputDocx
    Path for the output .docx file. Defaults to InputMd path with .docx extension.

.PARAMETER ReferenceDoc
    Path to a .docx style template (Pandoc --reference-doc). If not specified,
    Pandoc uses its built-in default styles.

.EXAMPLE
    .\convert-report.ps1 -InputMd ".\report.md" -ReferenceDoc ".\reference-style.docx"

.NOTES
    Requirements:
      - Pandoc (winget install --id JohnMacFarlane.Pandoc)
      - Microsoft Word (for post-processing)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InputMd,
    [string]$OutputDocx = "",
    [string]$ReferenceDoc = ""
)

$ErrorActionPreference = "Stop"

# Resolve paths
$InputMd = (Resolve-Path $InputMd).Path
if ($OutputDocx -eq "") {
    $OutputDocx = [System.IO.Path]::ChangeExtension($InputMd, ".docx")
}
$OutputDocx = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDocx)

Write-Host "Input:  $InputMd"
Write-Host "Output: $OutputDocx"

# Refresh PATH to find Pandoc if installed via winget in a prior session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path","User")

if (-not (Get-Command pandoc -ErrorAction SilentlyContinue)) {
    Write-Error "Pandoc not found. Install with: winget install --id JohnMacFarlane.Pandoc"
}

# Build Pandoc arguments
$pandocArgs = @($InputMd, "--from", "markdown", "--to", "docx",
                "--toc", "--toc-depth=3", "--output", $OutputDocx)

if ($ReferenceDoc -ne "") {
    $ReferenceDoc = (Resolve-Path $ReferenceDoc).Path
    $pandocArgs += "--reference-doc", $ReferenceDoc
    Write-Host "Style:  $ReferenceDoc"
}

# Run Pandoc
Write-Host "Running Pandoc..."
& pandoc @pandocArgs
if ($LASTEXITCODE -ne 0) { Write-Error "Pandoc failed (exit $LASTEXITCODE)" }
Write-Host "Pandoc conversion complete."

# Word COM post-processing
Write-Host "Running Word COM post-processing..."
$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open($OutputDocx)

    # Table borders
    foreach ($tbl in $doc.Tables) {
        $tbl.Borders.InsideLineStyle  = 1
        $tbl.Borders.OutsideLineStyle = 1
        $tbl.Borders.OutsideLineWidth = 4
        $tbl.Borders.InsideLineWidth  = 2
    }

    # Heading spacing, AllCaps, and blockquote gray italic styling
    foreach ($para in $doc.Paragraphs) {
        switch -Wildcard ($para.Style.NameLocal) {
            "Heading 1" {
                $para.Format.SpaceBefore  = 30
                $para.Format.SpaceAfter   = 8
                $para.Range.Font.Size     = 22
                $para.Range.Font.AllCaps  = $true
            }
            "Heading 2" {
                $para.Format.SpaceBefore  = 28
                $para.Format.SpaceAfter   = 6
                $para.Range.Font.Size     = 16
                $para.Range.Font.AllCaps  = $true
            }
            "Heading 3" {
                $para.Format.SpaceBefore  = 16
                $para.Format.SpaceAfter   = 4
                $para.Range.Font.Size     = 13
            }
            "Heading 4" {
                $para.Format.SpaceBefore  = 10
                $para.Format.SpaceAfter   = 3
            }
            "*Block Text*" {
                $para.Range.Font.Color   = 0xAAAAAA   # Light gray (R=G=B=170)
                $para.Range.Font.Size    = 10
                $para.Range.Font.Italic  = $true
            }
            "*Quote*" {
                $para.Range.Font.Color   = 0xAAAAAA
                $para.Range.Font.Size    = 10
                $para.Range.Font.Italic  = $true
            }
        }
    }

    $doc.Save()
    $doc.Close()
    Write-Host "Post-processing complete."
} finally {
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
}

Write-Host "Done: $OutputDocx"