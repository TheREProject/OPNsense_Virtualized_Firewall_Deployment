Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================
# Homelab Verification Tool
# Version 2.1.0
#
# PowerShell 5.1 compatible
# ASCII-only source
#
# OPNsense verification workflow:
#
#   1. SHA-256 checksum file
#   2. Compressed .bz2 image
#   3. Signature .sig
#   4. Mirror public key .pub
#   5. Independent public-key source #1
#   6. Optional independent public-key source #2
#   7. OpenSSL performs SHA-256 and signature verification
#   8. 7-Zip unpacks the .bz2 image
#
# The SHA-256 + signature sequence below matches the commands
# documented at docs.opnsense.org for verifying a downloaded image:
#   - SHA-256 is computed on the COMPRESSED .bz2 image.
#   - The .sig is base64-decoded, then verified against the
#     UNCOMPRESSED image (after unpacking), using the mirror's
#     .pub key. This was checked against the official docs and
#     is correct - do not "fix" it to verify against the .bz2 or
#     the checksum file instead.
#
# Changes in 2.1.0 (review fixes):
#   - Cleanup of the extracted-image working directory now runs on
#     EVERY exit path (success, failure, or unexpected error), not
#     only after a full success. Previously a failed run (e.g. a
#     signature mismatch) left the unpacked image sitting in %TEMP%
#     indefinitely.
#   - Selecting a missing/blank file field no longer risks an
#     unhandled binding error from Test-Path; empty paths are now
#     treated as "missing" up front.
#   - Log entries escape embedded CR/LF so a multi-line paste (e.g.
#     a PEM-formatted key) can't split into multiple fake-looking
#     log lines.
#   - OpenSSL/7-Zip discovery now checks known install locations
#     before falling back to whatever resolves on PATH, since a
#     verification tool trusting an arbitrary PATH-resolved
#     openssl.exe is a soft spot.
#   - If 7-Zip extracts more than one file from the image archive,
#     the tool now picks the largest one (and logs that it did so)
#     instead of silently grabbing whatever Get-ChildItem returned
#     first.
#   - The Verify button is disabled and the cursor shows "busy"
#     while a verification run is in progress. Note: the actual
#     work still runs on the UI thread, so the window can still
#     look non-responsive during large hashing/extraction steps -
#     this only adds a visual cue, it does not make the operation
#     background/async. Say the word if you want it truly threaded.
#   - Invoke-OpenSSL / Invoke-7Zip de-duplicated into one shared
#     helper (no behavior change).
#
# ============================================================

$Version = "2.1.0"

# ============================================================
# LOGGING
# ============================================================

$LogDirectory = Join-Path $env:USERPROFILE "HomelabVerification"
$LogFile = Join-Path $LogDirectory "verification.log"

if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Escape embedded newlines so one log entry always occupies exactly
    # one line. Without this, multi-line input (for example a
    # PEM-formatted public key pasted into a text box) could split
    # across several physical lines, making the log hard to parse and,
    # in principle, letting pasted text forge what looks like a
    # separate, unrelated log entry.
    $SafeMessage = $Message -replace "`r`n", "\n"
    $SafeMessage = $SafeMessage -replace "`r", "\n"
    $SafeMessage = $SafeMessage -replace "`n", "\n"

    Add-Content -Path $LogFile -Value "$Timestamp | $SafeMessage"
}

function New-VerificationId {
    return (Get-Date -Format "yyyyMMdd-HHmmss-fff")
}

Write-Log "Application started"
Write-Log "Version $Version"

# ============================================================
# HASH HELPERS
# ============================================================

function Get-TextSha256 {
    param(
        [string]$Text
    )

    $Sha256 = [System.Security.Cryptography.SHA256]::Create()

    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $HashBytes = $Sha256.ComputeHash($Bytes)

        return (
            [System.BitConverter]::ToString($HashBytes)
        ).Replace("-", "").ToLower()
    }
    finally {
        $Sha256.Dispose()
    }
}

# ============================================================
# PUBLIC KEY NORMALIZATION
#
# This removes differences caused by:
# - CRLF vs LF
# - leading/trailing whitespace
# - blank lines
#
# It does NOT modify the actual key material, and it is only ever
# used for the plaintext MATCH/MISMATCH comparison between pasted
# key text and the mirror's .pub file. The raw, untouched .pub file
# on disk is what is actually handed to openssl for the real
# cryptographic signature check.
# ============================================================

function Normalize-PublicKey {
    param(
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ""
    }

    $Normalized = $Text.Replace("`r`n", "`n")
    $Normalized = $Normalized.Replace("`r", "`n")

    $Lines = $Normalized -split "`n"

    $CleanLines = New-Object System.Collections.Generic.List[string]

    foreach ($Line in $Lines) {

        $Trimmed = $Line.Trim()

        if (-not [string]::IsNullOrWhiteSpace($Trimmed)) {
            $CleanLines.Add($Trimmed)
        }
    }

    return ($CleanLines -join "`n").Trim()
}

# ============================================================
# EXTERNAL TOOL HELPER
#
# Shared by Invoke-OpenSSL and Invoke-7Zip below (previously two
# copies of the same code).
# ============================================================

function ConvertTo-ProcessArgumentString {
    param(
        [string[]]$Arguments
    )

    # Windows PowerShell's Start-Process, when given -ArgumentList as
    # an ARRAY, does no quoting of its own - it just joins the
    # elements with plain spaces into one command-line string
    # (confirmed against the PowerShell-Docs team's own bug report,
    # see sources below). Quoting a single array element that
    # contains a space is *supposed* to survive that join, but in
    # practice this still isn't reliable across PowerShell/.NET
    # versions. The robust fix is to sidestep array mode entirely:
    # build the full, correctly escaped command-line string
    # ourselves and hand Start-Process that single string, which it
    # is documented to pass through untouched.
    #
    # This follows the standard Win32/CRT argv-escaping rules (the
    # same ones CommandLineToArgvW and every normal C-compiled
    # console app, including openssl.exe and 7z.exe, use to split
    # their own command line back apart):
    #   - wrap the argument in double quotes if it is empty or
    #     contains whitespace or a literal quote
    #   - a run of backslashes immediately before a literal quote
    #     must be doubled, and the quote itself backslash-escaped
    #   - a run of backslashes at the very end of a quoted argument
    #     must be doubled too, so it doesn't escape the closing quote

    $Parts = foreach ($Argument in $Arguments) {

        if ($Argument.Length -eq 0 -or $Argument -match '[\s"]') {

            $Escaped = $Argument -replace '(\\*)"', '$1$1\"'
            $Escaped = $Escaped -replace '(\\+)$', '$1$1'
            '"' + $Escaped + '"'
        }
        else {
            $Argument
        }
    }

    return ($Parts -join ' ')
}

function Invoke-ExternalTool {
    param(
        [string]$ExecutablePath,
        [string[]]$Arguments
    )

    $OutputFile = [System.IO.Path]::GetTempFileName()
    $ErrorFile = [System.IO.Path]::GetTempFileName()

    $ArgumentString = ConvertTo-ProcessArgumentString -Arguments $Arguments

    try {

        $Process = Start-Process `
            -FilePath $ExecutablePath `
            -ArgumentList $ArgumentString `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $OutputFile `
            -RedirectStandardError $ErrorFile

        # Get-Content -Raw returns $null (not "") for a 0-byte file.
        # A process that writes nothing to stdout/stderr - which
        # happens whenever it fails before printing anything - would
        # otherwise make the .Trim() calls below throw "You cannot
        # call a method on a null-valued expression", masking the
        # real error underneath a useless exception.

        $StdOut = ""

        if (Test-Path $OutputFile) {

            $CapturedOut = Get-Content `
                -Path $OutputFile `
                -Raw `
                -ErrorAction SilentlyContinue

            if ($null -ne $CapturedOut) {
                $StdOut = $CapturedOut
            }
        }

        $StdErr = ""

        if (Test-Path $ErrorFile) {

            $CapturedErr = Get-Content `
                -Path $ErrorFile `
                -Raw `
                -ErrorAction SilentlyContinue

            if ($null -ne $CapturedErr) {
                $StdErr = $CapturedErr
            }
        }

        return @{
            ExitCode = $Process.ExitCode
            StdOut   = $StdOut.Trim()
            StdErr   = $StdErr.Trim()
        }
    }
    finally {

        Remove-Item $OutputFile -Force -ErrorAction SilentlyContinue
        Remove-Item $ErrorFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-OpenSSL {
    param(
        [string]$OpenSSLPath,
        [string[]]$Arguments
    )

    return Invoke-ExternalTool `
        -ExecutablePath $OpenSSLPath `
        -Arguments $Arguments
}

function Invoke-7Zip {
    param(
        [string]$SevenZipPath,
        [string[]]$Arguments
    )

    return Invoke-ExternalTool `
        -ExecutablePath $SevenZipPath `
        -Arguments $Arguments
}

# ============================================================
# FIND OPENSSL
#
# Known install locations are checked BEFORE falling back to
# whatever "openssl.exe" resolves to on PATH. For a tool whose
# entire job is cryptographic verification, silently trusting
# the first openssl.exe found on PATH is a soft spot (PATH order
# can be influenced by other installed software, or, worst case,
# by something malicious earlier in PATH). The resolved path is
# still logged either way, so it's auditable.
# ============================================================

function Find-OpenSSL {

    $Candidates = New-Object System.Collections.Generic.List[string]

    $Candidates.Add("$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe")
    $Candidates.Add("$env:ProgramFiles\OpenSSL-Win32\bin\openssl.exe")
    $Candidates.Add("${env:ProgramFiles(x86)}\OpenSSL-Win32\bin\openssl.exe")

    if ($env:ChocolateyInstall) {
        $Candidates.Add(
            (Join-Path $env:ChocolateyInstall "bin\openssl.exe")
        )
    }

    foreach ($Candidate in $Candidates) {

        if (Test-Path $Candidate) {
            return $Candidate
        }
    }

    # PATH fallback, checked last.
    $Command = Get-Command openssl.exe -ErrorAction SilentlyContinue

    if ($null -ne $Command) {
        return $Command.Source
    }

    return $null
}

# ============================================================
# FIND 7-ZIP
# Same reasoning as Find-OpenSSL above.
# ============================================================

function Find-7Zip {

    $Candidates = @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
    )

    foreach ($Candidate in $Candidates) {

        if (Test-Path $Candidate) {
            return $Candidate
        }
    }

    # PATH fallback, checked last.
    $Command = Get-Command 7z.exe -ErrorAction SilentlyContinue

    if ($null -ne $Command) {
        return $Command.Source
    }

    return $null
}

# ============================================================
# CHECKSUM FILE PARSER
# ============================================================

function Get-ExpectedChecksum {
    param(
        [string]$ChecksumFile,
        [string]$TargetFileName
    )

    $Lines = Get-Content `
        -Path $ChecksumFile `
        -ErrorAction Stop

    foreach ($Line in $Lines) {

        $Trimmed = $Line.Trim()

        if ([string]::IsNullOrWhiteSpace($Trimmed)) {
            continue
        }

        if ($Trimmed.StartsWith("#")) {
            continue
        }

        # OPNsense's checksums file is written by FreeBSD's native
        # "sha256(1)" tool (BSD format), not GNU coreutils'
        # sha256sum - the actual line shape is:
        #   SHA256 (OPNsense-26.7-dvd-amd64.iso.bz2) = <hash>
        # Confirmed against a real release's checksums file. Try
        # this format first.

        if ($Trimmed -match '^SHA256\s*\(([^)]+)\)\s*=\s*([A-Fa-f0-9]{64})\s*$') {

            $FileName = $Matches[1].Trim()
            $Hash = $Matches[2].ToLower()

            if ($FileName -eq $TargetFileName) {
                return $Hash
            }

            continue
        }

        # GNU coreutils "sha256sum" format, kept for compatibility
        # with checksum files produced by other tools:
        #   <hash>  <filename>
        #   <hash> *<filename>

        if ($Trimmed -match '^([A-Fa-f0-9]{64})\s+\*?(.+)$') {

            $Hash = $Matches[1].ToLower()
            $FileName = $Matches[2].Trim()

            if ($FileName -eq $TargetFileName) {
                return $Hash
            }
        }
    }

    return $null
}

# ============================================================
# FORM
# ============================================================

$form = New-Object System.Windows.Forms.Form

$form.Text = "Homelab Verification Tool V$Version"
$form.Size = New-Object System.Drawing.Size(930, 790)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# ============================================================
# TAB CONTROL
# ============================================================

$tabs = New-Object System.Windows.Forms.TabControl

$tabs.Location = New-Object System.Drawing.Point(10, 10)
$tabs.Size = New-Object System.Drawing.Size(895, 710)

$form.Controls.Add($tabs)

# ============================================================
# STRING COMPARISON TAB
# ============================================================

$stringTab = New-Object System.Windows.Forms.TabPage
$stringTab.Text = "String Comparison"

$tabs.TabPages.Add($stringTab)

$stringBoxes = @()

for ($i = 1; $i -le 5; $i++) {

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Source $i"
    $label.Location = New-Object System.Drawing.Point(
        20,
        (20 + (($i - 1) * 90))
    )
    $label.Size = New-Object System.Drawing.Size(100, 25)

    $stringTab.Controls.Add($label)

    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ScrollBars = "Vertical"
    $box.Location = New-Object System.Drawing.Point(
        120,
        (15 + (($i - 1) * 90))
    )
    $box.Size = New-Object System.Drawing.Size(720, 65)

    $stringTab.Controls.Add($box)

    $stringBoxes += $box
}

$compareStringsButton = New-Object System.Windows.Forms.Button
$compareStringsButton.Text = "Compare Strings"
$compareStringsButton.Location = New-Object System.Drawing.Point(20, 475)
$compareStringsButton.Size = New-Object System.Drawing.Size(150, 35)

$stringTab.Controls.Add($compareStringsButton)

$clearStringsButton = New-Object System.Windows.Forms.Button
$clearStringsButton.Text = "Clear"
$clearStringsButton.Location = New-Object System.Drawing.Point(180, 475)
$clearStringsButton.Size = New-Object System.Drawing.Size(100, 35)

$stringTab.Controls.Add($clearStringsButton)

$stringResult = New-Object System.Windows.Forms.Label
$stringResult.Text = "Result: Waiting"
$stringResult.Location = New-Object System.Drawing.Point(300, 480)
$stringResult.Size = New-Object System.Drawing.Size(500, 30)
$stringResult.Font = New-Object System.Drawing.Font(
    "Segoe UI",
    11,
    [System.Drawing.FontStyle]::Bold
)

$stringTab.Controls.Add($stringResult)

$stringHashLabel = New-Object System.Windows.Forms.Label
$stringHashLabel.Text = "SHA-256 values are written to the log."
$stringHashLabel.Location = New-Object System.Drawing.Point(20, 525)
$stringHashLabel.Size = New-Object System.Drawing.Size(600, 25)

$stringTab.Controls.Add($stringHashLabel)

$compareStringsButton.Add_Click({

    $VerificationId = New-VerificationId

    Write-Log "Verification ID $VerificationId | String comparison started"

    $Values = @()

    for ($i = 0; $i -lt $stringBoxes.Count; $i++) {

        $Value = $stringBoxes[$i].Text.Trim()

        if ([string]::IsNullOrWhiteSpace($Value)) {
            continue
        }

        $Hash = Get-TextSha256 -Text $Value

        Write-Log (
            "Verification ID $VerificationId | " +
            "Source $($i + 1) | " +
            "Length=$($Value.Length) | " +
            "SHA256=$Hash | " +
            "Value=$Value"
        )

        $Values += $Value
    }

    if ($Values.Count -lt 2) {

        $stringResult.Text = "Result: Need at least two values"

        Write-Log (
            "Verification ID $VerificationId | " +
            "String comparison failed | Fewer than two values"
        )

        return
    }

    $FirstValue = $Values[0]
    $Match = $true

    foreach ($Value in $Values) {

        if ($Value -cne $FirstValue) {
            $Match = $false
            break
        }
    }

    if ($Match) {

        $stringResult.Text = "Result: MATCH"

        Write-Log (
            "Verification ID $VerificationId | " +
            "String comparison result=MATCH"
        )
    }
    else {

        $stringResult.Text = "Result: MISMATCH"

        Write-Log (
            "Verification ID $VerificationId | " +
            "String comparison result=MISMATCH"
        )
    }
})

$clearStringsButton.Add_Click({

    foreach ($Box in $stringBoxes) {
        $Box.Clear()
    }

    $stringResult.Text = "Result: Waiting"

    Write-Log "String comparison fields cleared"
})

# ============================================================
# OPNsense TAB
# ============================================================

$opnTab = New-Object System.Windows.Forms.TabPage
$opnTab.Text = "OPNsense Verification"

$tabs.TabPages.Add($opnTab)

# ============================================================
# SECTION 1
# REQUIRED OPNsense FILES
# ============================================================

$header1 = New-Object System.Windows.Forms.Label
$header1.Text = "1. OPNsense Verification Files"
$header1.Location = New-Object System.Drawing.Point(20, 15)
$header1.Size = New-Object System.Drawing.Size(500, 30)
$header1.Font = New-Object System.Drawing.Font(
    "Segoe UI",
    12,
    [System.Drawing.FontStyle]::Bold
)

$opnTab.Controls.Add($header1)

# ------------------------------------------------------------
# SHA-256 checksum file
# ------------------------------------------------------------

$checksumLabel = New-Object System.Windows.Forms.Label
$checksumLabel.Text = "SHA-256 file"
$checksumLabel.Location = New-Object System.Drawing.Point(20, 55)
$checksumLabel.Size = New-Object System.Drawing.Size(130, 25)

$opnTab.Controls.Add($checksumLabel)

$checksumBox = New-Object System.Windows.Forms.TextBox
$checksumBox.Location = New-Object System.Drawing.Point(150, 52)
$checksumBox.Size = New-Object System.Drawing.Size(600, 25)

$opnTab.Controls.Add($checksumBox)

$checksumBrowse = New-Object System.Windows.Forms.Button
$checksumBrowse.Text = "Browse..."
$checksumBrowse.Location = New-Object System.Drawing.Point(760, 50)
$checksumBrowse.Size = New-Object System.Drawing.Size(90, 30)

$opnTab.Controls.Add($checksumBrowse)

# ------------------------------------------------------------
# Compressed image
# ------------------------------------------------------------

$imageLabel = New-Object System.Windows.Forms.Label
$imageLabel.Text = "Image .bz2"
$imageLabel.Location = New-Object System.Drawing.Point(20, 90)
$imageLabel.Size = New-Object System.Drawing.Size(130, 25)

$opnTab.Controls.Add($imageLabel)

$imageBox = New-Object System.Windows.Forms.TextBox
$imageBox.Location = New-Object System.Drawing.Point(150, 87)
$imageBox.Size = New-Object System.Drawing.Size(600, 25)

$opnTab.Controls.Add($imageBox)

$imageBrowse = New-Object System.Windows.Forms.Button
$imageBrowse.Text = "Browse..."
$imageBrowse.Location = New-Object System.Drawing.Point(760, 85)
$imageBrowse.Size = New-Object System.Drawing.Size(90, 30)

$opnTab.Controls.Add($imageBrowse)

# ------------------------------------------------------------
# Signature
# ------------------------------------------------------------

$sigLabel = New-Object System.Windows.Forms.Label
$sigLabel.Text = "Signature .sig"
$sigLabel.Location = New-Object System.Drawing.Point(20, 125)
$sigLabel.Size = New-Object System.Drawing.Size(130, 25)

$opnTab.Controls.Add($sigLabel)

$sigBox = New-Object System.Windows.Forms.TextBox
$sigBox.Location = New-Object System.Drawing.Point(150, 122)
$sigBox.Size = New-Object System.Drawing.Size(600, 25)

$opnTab.Controls.Add($sigBox)

$sigBrowse = New-Object System.Windows.Forms.Button
$sigBrowse.Text = "Browse..."
$sigBrowse.Location = New-Object System.Drawing.Point(760, 120)
$sigBrowse.Size = New-Object System.Drawing.Size(90, 30)

$opnTab.Controls.Add($sigBrowse)

# ------------------------------------------------------------
# Mirror public key
# ------------------------------------------------------------

$mirrorLabel = New-Object System.Windows.Forms.Label
$mirrorLabel.Text = "Mirror .pub"
$mirrorLabel.Location = New-Object System.Drawing.Point(20, 160)
$mirrorLabel.Size = New-Object System.Drawing.Size(130, 25)

$opnTab.Controls.Add($mirrorLabel)

$mirrorBox = New-Object System.Windows.Forms.TextBox
$mirrorBox.Location = New-Object System.Drawing.Point(150, 157)
$mirrorBox.Size = New-Object System.Drawing.Size(600, 25)

$opnTab.Controls.Add($mirrorBox)

$mirrorBrowse = New-Object System.Windows.Forms.Button
$mirrorBrowse.Text = "Browse..."
$mirrorBrowse.Location = New-Object System.Drawing.Point(760, 155)
$mirrorBrowse.Size = New-Object System.Drawing.Size(90, 30)

$opnTab.Controls.Add($mirrorBrowse)

# ============================================================
# SECTION 2
# INDEPENDENT PUBLIC KEY SOURCES
# ============================================================

$header2 = New-Object System.Windows.Forms.Label
$header2.Text = "2. Independent Public-Key Verification"
$header2.Location = New-Object System.Drawing.Point(20, 205)
$header2.Size = New-Object System.Drawing.Size(600, 30)
$header2.Font = New-Object System.Drawing.Font(
    "Segoe UI",
    12,
    [System.Drawing.FontStyle]::Bold
)

$opnTab.Controls.Add($header2)

$keyInfo = New-Object System.Windows.Forms.Label
$keyInfo.Text = "Paste the public key copied from an independent OPNsense source."
$keyInfo.Location = New-Object System.Drawing.Point(20, 235)
$keyInfo.Size = New-Object System.Drawing.Size(700, 25)

$opnTab.Controls.Add($keyInfo)

# ------------------------------------------------------------
# Independent source 1
# ------------------------------------------------------------

$key1Label = New-Object System.Windows.Forms.Label
$key1Label.Text = "Independent #1"
$key1Label.Location = New-Object System.Drawing.Point(20, 270)
$key1Label.Size = New-Object System.Drawing.Size(130, 25)

$opnTab.Controls.Add($key1Label)

$key1Box = New-Object System.Windows.Forms.TextBox
$key1Box.Multiline = $true
$key1Box.ScrollBars = "Vertical"
$key1Box.Location = New-Object System.Drawing.Point(150, 267)
$key1Box.Size = New-Object System.Drawing.Size(700, 75)

$opnTab.Controls.Add($key1Box)

# ------------------------------------------------------------
# Independent source 2
# ------------------------------------------------------------

$key2Label = New-Object System.Windows.Forms.Label
$key2Label.Text = "Independent #2"
$key2Label.Location = New-Object System.Drawing.Point(20, 355)
$key2Label.Size = New-Object System.Drawing.Size(130, 25)

$opnTab.Controls.Add($key2Label)

$key2Box = New-Object System.Windows.Forms.TextBox
$key2Box.Multiline = $true
$key2Box.ScrollBars = "Vertical"
$key2Box.Location = New-Object System.Drawing.Point(150, 352)
$key2Box.Size = New-Object System.Drawing.Size(700, 75)

$opnTab.Controls.Add($key2Box)

# ============================================================
# SECTION 3
# TOOL DISCOVERY
# ============================================================

$header3 = New-Object System.Windows.Forms.Label
$header3.Text = "3. Verification Tools"
$header3.Location = New-Object System.Drawing.Point(20, 445)
$header3.Size = New-Object System.Drawing.Size(400, 30)
$header3.Font = New-Object System.Drawing.Font(
    "Segoe UI",
    12,
    [System.Drawing.FontStyle]::Bold
)

$opnTab.Controls.Add($header3)

$opensslStatus = New-Object System.Windows.Forms.Label
$opensslStatus.Text = "OpenSSL: checking..."
$opensslStatus.Location = New-Object System.Drawing.Point(20, 480)
$opensslStatus.Size = New-Object System.Drawing.Size(400, 25)

$opnTab.Controls.Add($opensslStatus)

$sevenZipStatus = New-Object System.Windows.Forms.Label
$sevenZipStatus.Text = "7-Zip: checking..."
$sevenZipStatus.Location = New-Object System.Drawing.Point(450, 480)
$sevenZipStatus.Size = New-Object System.Drawing.Size(400, 25)

$opnTab.Controls.Add($sevenZipStatus)

# ============================================================
# SECTION 4
# VERIFICATION STATUS
# ============================================================

$header4 = New-Object System.Windows.Forms.Label
$header4.Text = "4. Verification Status"
$header4.Location = New-Object System.Drawing.Point(20, 515)
$header4.Size = New-Object System.Drawing.Size(400, 30)
$header4.Font = New-Object System.Drawing.Font(
    "Segoe UI",
    12,
    [System.Drawing.FontStyle]::Bold
)

$opnTab.Controls.Add($header4)

$shaStatus = New-Object System.Windows.Forms.Label
$shaStatus.Text = "SHA-256: WAITING"
$shaStatus.Location = New-Object System.Drawing.Point(20, 550)
$shaStatus.Size = New-Object System.Drawing.Size(260, 25)

$opnTab.Controls.Add($shaStatus)

$key1Status = New-Object System.Windows.Forms.Label
$key1Status.Text = "Public Key #1: WAITING"
$key1Status.Location = New-Object System.Drawing.Point(300, 550)
$key1Status.Size = New-Object System.Drawing.Size(260, 25)

$opnTab.Controls.Add($key1Status)

$key2Status = New-Object System.Windows.Forms.Label
$key2Status.Text = "Public Key #2: NOT USED"
$key2Status.Location = New-Object System.Drawing.Point(580, 550)
$key2Status.Size = New-Object System.Drawing.Size(270, 25)

$opnTab.Controls.Add($key2Status)

$unpackStatus = New-Object System.Windows.Forms.Label
$unpackStatus.Text = "Image Unpack: WAITING"
$unpackStatus.Location = New-Object System.Drawing.Point(20, 580)
$unpackStatus.Size = New-Object System.Drawing.Size(260, 25)

$opnTab.Controls.Add($unpackStatus)

$signatureStatus = New-Object System.Windows.Forms.Label
$signatureStatus.Text = "Signature: WAITING"
$signatureStatus.Location = New-Object System.Drawing.Point(300, 580)
$signatureStatus.Size = New-Object System.Drawing.Size(260, 25)

$opnTab.Controls.Add($signatureStatus)

$overallStatus = New-Object System.Windows.Forms.Label
$overallStatus.Text = "OVERALL RESULT: WAITING"
$overallStatus.Location = New-Object System.Drawing.Point(580, 580)
$overallStatus.Size = New-Object System.Drawing.Size(270, 30)
$overallStatus.Font = New-Object System.Drawing.Font(
    "Segoe UI",
    11,
    [System.Drawing.FontStyle]::Bold
)

$opnTab.Controls.Add($overallStatus)

# ============================================================
# VERIFY BUTTON
# ============================================================

$verifyButton = New-Object System.Windows.Forms.Button
$verifyButton.Text = "Verify OPNsense Image"
$verifyButton.Location = New-Object System.Drawing.Point(20, 620)
$verifyButton.Size = New-Object System.Drawing.Size(190, 40)

$opnTab.Controls.Add($verifyButton)

# ============================================================
# SAVED IMAGE STATUS
#
# Shows where the verified, uncompressed image ended up after a
# successful run - either a permanent location the user picked, or
# a note that it was left in the temporary working folder (and
# therefore removed once cleanup runs).
# ============================================================

$savedImageStatus = New-Object System.Windows.Forms.Label
$savedImageStatus.Text = "Saved Image: (not yet available)"
$savedImageStatus.Location = New-Object System.Drawing.Point(20, 670)
$savedImageStatus.Size = New-Object System.Drawing.Size(850, 25)

$opnTab.Controls.Add($savedImageStatus)

# ============================================================
# BROWSE EVENTS
# ============================================================

$checksumBrowse.Add_Click({

    $Dialog = New-Object System.Windows.Forms.OpenFileDialog

    $Dialog.Title = "Select OPNsense SHA-256 checksum file"
    $Dialog.Filter = "SHA-256 files (*.sha256)|*.sha256|All files (*.*)|*.*"

    if ($Dialog.ShowDialog() -eq "OK") {

        $checksumBox.Text = $Dialog.FileName

        Write-Log (
            "Checksum file selected | " +
            "Path=$($Dialog.FileName)"
        )
    }
})

$imageBrowse.Add_Click({

    $Dialog = New-Object System.Windows.Forms.OpenFileDialog

    $Dialog.Title = "Select OPNsense compressed image"
    $Dialog.Filter = "BZip2 images (*.bz2)|*.bz2|All files (*.*)|*.*"

    if ($Dialog.ShowDialog() -eq "OK") {

        $imageBox.Text = $Dialog.FileName

        Write-Log (
            "Compressed image selected | " +
            "Path=$($Dialog.FileName)"
        )
    }
})

$sigBrowse.Add_Click({

    $Dialog = New-Object System.Windows.Forms.OpenFileDialog

    $Dialog.Title = "Select OPNsense signature"
    $Dialog.Filter = "Signature files (*.sig)|*.sig|All files (*.*)|*.*"

    if ($Dialog.ShowDialog() -eq "OK") {

        $sigBox.Text = $Dialog.FileName

        Write-Log (
            "Signature selected | " +
            "Path=$($Dialog.FileName)"
        )
    }
})

$mirrorBrowse.Add_Click({

    $Dialog = New-Object System.Windows.Forms.OpenFileDialog

    $Dialog.Title = "Select OPNsense mirror public key"
    $Dialog.Filter = "Public key files (*.pub)|*.pub|All files (*.*)|*.*"

    if ($Dialog.ShowDialog() -eq "OK") {

        $mirrorBox.Text = $Dialog.FileName

        Write-Log (
            "Mirror public key selected | " +
            "Path=$($Dialog.FileName)"
        )
    }
})

# ============================================================
# MAIN VERIFICATION
# ============================================================

$verifyButton.Add_Click({

    $VerificationId = New-VerificationId

    # Tracked so the finally block below can always clean up the
    # extraction working directory, however this run ends.
    $WorkingDirectory = $null

    $verifyButton.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor

    try {

        Write-Log (
            "Verification ID $VerificationId | " +
            "OPNsense verification started"
        )

        # --------------------------------------------------------
        # Reset status
        # --------------------------------------------------------

        $shaStatus.Text = "SHA-256: RUNNING"
        $key1Status.Text = "Public Key #1: RUNNING"
        $key2Status.Text = "Public Key #2: NOT USED"
        $unpackStatus.Text = "Image Unpack: WAITING"
        $signatureStatus.Text = "Signature: WAITING"
        $overallStatus.Text = "OVERALL RESULT: RUNNING"
        $savedImageStatus.Text = "Saved Image: (not yet available)"

        # --------------------------------------------------------
        # Locate tools
        # --------------------------------------------------------

        $OpenSSLPath = Find-OpenSSL
        $SevenZipPath = Find-7Zip

        if ($null -eq $OpenSSLPath) {

            $opensslStatus.Text = "OpenSSL: NOT FOUND"

            Write-Log (
                "Verification ID $VerificationId | " +
                "OpenSSL executable not found"
            )

            [System.Windows.Forms.MessageBox]::Show(
                "OpenSSL was not found.`r`n`r`n" +
                "Install OpenSSL and make sure openssl.exe " +
                "is available in PATH or installed in a standard location.",
                "OpenSSL Not Found",
                "OK",
                "Error"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        $opensslStatus.Text = "OpenSSL: FOUND"

        Write-Log (
            "Verification ID $VerificationId | " +
            "OpenSSL=$OpenSSLPath"
        )

        if ($null -eq $SevenZipPath) {

            $sevenZipStatus.Text = "7-Zip: NOT FOUND"

            Write-Log (
                "Verification ID $VerificationId | " +
                "7-Zip executable not found"
            )

            [System.Windows.Forms.MessageBox]::Show(
                "7-Zip was not found.`r`n`r`n" +
                "Install 7-Zip and make sure 7z.exe " +
                "is available in PATH or installed in a standard location.",
                "7-Zip Not Found",
                "OK",
                "Error"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        $sevenZipStatus.Text = "7-Zip: FOUND"

        Write-Log (
            "Verification ID $VerificationId | " +
            "7-Zip=$SevenZipPath"
        )

        # --------------------------------------------------------
        # Read paths
        # --------------------------------------------------------

        $ChecksumPath = $checksumBox.Text.Trim()
        $ImagePath = $imageBox.Text.Trim()
        $SigPath = $sigBox.Text.Trim()
        $MirrorPath = $mirrorBox.Text.Trim()

        # --------------------------------------------------------
        # Validate four required files
        #
        # Blank fields are treated as "missing" before Test-Path
        # ever sees them - Test-Path -LiteralPath "" throws a
        # parameter-binding error rather than returning $false, so
        # clicking Verify with an empty field used to be able to
        # blow past this friendly error entirely.
        # --------------------------------------------------------

        $Required = @(
            @{
                Name = "SHA-256 checksum file"
                Path = $ChecksumPath
            },
            @{
                Name = "Compressed image"
                Path = $ImagePath
            },
            @{
                Name = "Signature file"
                Path = $SigPath
            },
            @{
                Name = "Mirror public key"
                Path = $MirrorPath
            }
        )

        foreach ($Item in $Required) {

            $PathIsUsable = (-not [string]::IsNullOrWhiteSpace($Item.Path)) `
                -and (Test-Path -LiteralPath $Item.Path)

            if (-not $PathIsUsable) {

                [System.Windows.Forms.MessageBox]::Show(
                    "$($Item.Name) was not found.",
                    "Verification Error",
                    "OK",
                    "Error"
                )

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Missing file | " +
                    "$($Item.Name) | " +
                    "Path=$($Item.Path)"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }
        }

        # ========================================================
        # STEP 1
        # OPENSSL SHA-256 OF COMPRESSED IMAGE
        # ========================================================

        Write-Log (
            "Verification ID $VerificationId | " +
            "Step 1 | OpenSSL SHA-256 started"
        )

        $ImageInfo = Get-Item -LiteralPath $ImagePath
        $ImageFileName = $ImageInfo.Name

        try {

            # This intentionally follows the OPNsense command:
            #
            # openssl sha256 <image>.bz2

            $ShaResult = Invoke-OpenSSL `
                -OpenSSLPath $OpenSSLPath `
                -Arguments @(
                    "sha256",
                    $ImagePath
                )

            Write-Log (
                "Verification ID $VerificationId | " +
                "OpenSSL SHA-256 exit code=$($ShaResult.ExitCode)"
            )

            Write-Log (
                "Verification ID $VerificationId | " +
                "OpenSSL SHA-256 output=$($ShaResult.StdOut)"
            )

            if ($ShaResult.ExitCode -ne 0) {

                $shaStatus.Text = "SHA-256: OPENSSL ERROR"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "OpenSSL SHA-256 failed | " +
                    "Error=$($ShaResult.StdErr)"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }

            # ----------------------------------------------------
            # Extract the 64-character SHA-256 value from output.
            # ----------------------------------------------------

            if ($ShaResult.StdOut -notmatch '([A-Fa-f0-9]{64})') {

                $shaStatus.Text = "SHA-256: HASH NOT FOUND"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Could not parse SHA-256 from OpenSSL output"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }

            $CalculatedHash = $Matches[1].ToLower()

            # ----------------------------------------------------
            # Read expected hash from checksum file.
            # ----------------------------------------------------

            $ExpectedHash = Get-ExpectedChecksum `
                -ChecksumFile $ChecksumPath `
                -TargetFileName $ImageFileName

            if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {

                $shaStatus.Text = "SHA-256: HASH NOT FOUND IN CHECKSUM FILE"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Expected checksum not found for " +
                    "$ImageFileName"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }

            Write-Log (
                "Verification ID $VerificationId | " +
                "Calculated SHA256=$CalculatedHash"
            )

            Write-Log (
                "Verification ID $VerificationId | " +
                "Expected SHA256=$ExpectedHash"
            )

            if ($CalculatedHash -eq $ExpectedHash) {

                $shaStatus.Text = "SHA-256: MATCH"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "SHA-256 result=MATCH"
                )
            }
            else {

                $shaStatus.Text = "SHA-256: MISMATCH"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "SHA-256 result=MISMATCH"
                )

                [System.Windows.Forms.MessageBox]::Show(
                    "The compressed image SHA-256 does not match " +
                    "the OPNsense checksum file.`r`n`r`n" +
                    "Do not continue with this image.",
                    "SHA-256 Verification Failed",
                    "OK",
                    "Error"
                )

                $overallStatus.Text = "OVERALL RESULT: NOT VERIFIED"

                return
            }
        }
        catch {

            $shaStatus.Text = "SHA-256: ERROR"

            Write-Log (
                "Verification ID $VerificationId | " +
                "SHA-256 exception | " +
                "Error=$($_.Exception.Message)"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        # ========================================================
        # STEP 2
        # PUBLIC KEY COMPARISON
        # ========================================================

        Write-Log (
            "Verification ID $VerificationId | " +
            "Step 2 | Public-key comparison started"
        )

        try {

            # ----------------------------------------------------
            # Read mirror .pub
            # ----------------------------------------------------

            $MirrorRaw = Get-Content `
                -Path $MirrorPath `
                -Raw `
                -ErrorAction Stop

            $MirrorKey = Normalize-PublicKey -Text $MirrorRaw

            $MirrorHash = Get-TextSha256 -Text $MirrorKey

            Write-Log (
                "Verification ID $VerificationId | " +
                "Mirror public-key SHA256=$MirrorHash"
            )

            # ----------------------------------------------------
            # Independent source #1
            # ----------------------------------------------------

            $Independent1 = Normalize-PublicKey `
                -Text $key1Box.Text

            if ([string]::IsNullOrWhiteSpace($Independent1)) {

                $key1Status.Text = "Public Key #1: EMPTY"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Independent public-key source #1 is empty"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }

            $Independent1Hash = Get-TextSha256 `
                -Text $Independent1

            Write-Log (
                "Verification ID $VerificationId | " +
                "Independent source #1 SHA256=$Independent1Hash"
            )

            $Key1Match = ($MirrorKey -ceq $Independent1)

            if ($Key1Match) {

                $key1Status.Text = "Public Key #1: MATCH"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Public key #1 result=MATCH"
                )
            }
            else {

                $key1Status.Text = "Public Key #1: MISMATCH"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Public key #1 result=MISMATCH"
                )

                [System.Windows.Forms.MessageBox]::Show(
                    "The mirror public key does not match " +
                    "independent source #1.`r`n`r`n" +
                    "Do not continue with this image.",
                    "Public Key Verification Failed",
                    "OK",
                    "Error"
                )

                $overallStatus.Text = "OVERALL RESULT: NOT VERIFIED"

                return
            }

            # ----------------------------------------------------
            # Independent source #2
            # Optional
            # ----------------------------------------------------

            $Independent2 = Normalize-PublicKey `
                -Text $key2Box.Text

            if ([string]::IsNullOrWhiteSpace($Independent2)) {

                $key2Status.Text = "Public Key #2: NOT USED"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Independent public-key source #2 not supplied"
                )
            }
            else {

                $Independent2Hash = Get-TextSha256 `
                    -Text $Independent2

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Independent source #2 SHA256=$Independent2Hash"
                )

                $Key2Match = ($MirrorKey -ceq $Independent2)

                if ($Key2Match) {

                    $key2Status.Text = "Public Key #2: MATCH"

                    Write-Log (
                        "Verification ID $VerificationId | " +
                        "Public key #2 result=MATCH"
                    )
                }
                else {

                    $key2Status.Text = "Public Key #2: MISMATCH"

                    Write-Log (
                        "Verification ID $VerificationId | " +
                        "Public key #2 result=MISMATCH"
                    )

                    [System.Windows.Forms.MessageBox]::Show(
                        "The mirror public key does not match " +
                        "independent source #2.`r`n`r`n" +
                        "Do not continue with this image.",
                        "Public Key Verification Failed",
                        "OK",
                        "Error"
                    )

                    $overallStatus.Text = "OVERALL RESULT: NOT VERIFIED"

                    return
                }
            }
        }
        catch {

            $key1Status.Text = "Public Key #1: ERROR"

            Write-Log (
                "Verification ID $VerificationId | " +
                "Public-key comparison error | " +
                "Error=$($_.Exception.Message)"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        # ========================================================
        # STEP 3
        # UNPACK .BZ2 WITH 7-ZIP
        # ========================================================

        Write-Log (
            "Verification ID $VerificationId | " +
            "Step 3 | 7-Zip image extraction started"
        )

        $WorkingDirectory = Join-Path `
            $env:TEMP `
            ("HomelabVerification-" + $VerificationId)

        try {

            New-Item `
                -ItemType Directory `
                -Path $WorkingDirectory `
                -Force | Out-Null

            # ----------------------------------------------------
            # 7-Zip extracts the .bz2.
            #
            # This is the Windows equivalent of:
            #
            # bunzip2 OPNsense-<filename>.bz2
            # ----------------------------------------------------

            $SevenZipResult = Invoke-7Zip `
                -SevenZipPath $SevenZipPath `
                -Arguments @(
                    "e",
                    "-y",
                    "-o$WorkingDirectory",
                    $ImagePath
                )

            Write-Log (
                "Verification ID $VerificationId | " +
                "7-Zip exit code=$($SevenZipResult.ExitCode)"
            )

            if (-not [string]::IsNullOrWhiteSpace(
                $SevenZipResult.StdOut
            )) {

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "7-Zip output=$($SevenZipResult.StdOut)"
                )
            }

            if ($SevenZipResult.ExitCode -ne 0) {

                $unpackStatus.Text = "Image Unpack: FAILED"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "7-Zip extraction failed | " +
                    "Error=$($SevenZipResult.StdErr)"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }

            # ----------------------------------------------------
            # Find the resulting uncompressed image.
            #
            # If 7-Zip produced more than one file (unexpected for
            # a .bz2, but not impossible), pick the largest rather
            # than blindly using whatever Get-ChildItem happened to
            # return first.
            # ----------------------------------------------------

            $ExtractedFiles = Get-ChildItem `
                -Path $WorkingDirectory `
                -File `
                -Recurse

            if ($ExtractedFiles.Count -eq 0) {

                $unpackStatus.Text = "Image Unpack: NO IMAGE FOUND"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "7-Zip completed but no output image was found"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }

            if ($ExtractedFiles.Count -gt 1) {

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "7-Zip produced $($ExtractedFiles.Count) files " +
                    "from a single .bz2 archive; using the largest " +
                    "as the image"
                )
            }

            $UncompressedImage = (
                $ExtractedFiles |
                Sort-Object Length -Descending |
                Select-Object -First 1
            ).FullName

            $unpackStatus.Text = "Image Unpack: SUCCESS"

            Write-Log (
                "Verification ID $VerificationId | " +
                "Uncompressed image=$UncompressedImage"
            )
        }
        catch {

            $unpackStatus.Text = "Image Unpack: ERROR"

            Write-Log (
                "Verification ID $VerificationId | " +
                "7-Zip exception | " +
                "Error=$($_.Exception.Message)"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        # ========================================================
        # STEP 4
        # BASE64 DECODE SIGNATURE
        # ========================================================

        Write-Log (
            "Verification ID $VerificationId | " +
            "Step 4 | OpenSSL Base64 decoding started"
        )

        $DecodedSignature = Join-Path `
            $WorkingDirectory `
            "image.sig"

        try {

            # Exact OPNsense workflow:
            #
            # openssl base64 -d
            #   -in <image>.sig
            #   -out /tmp/image.sig

            $DecodeResult = Invoke-OpenSSL `
                -OpenSSLPath $OpenSSLPath `
                -Arguments @(
                    "base64",
                    "-d",
                    "-in",
                    $SigPath,
                    "-out",
                    $DecodedSignature
                )

            Write-Log (
                "Verification ID $VerificationId | " +
                "OpenSSL Base64 exit code=$($DecodeResult.ExitCode)"
            )

            if ($DecodeResult.ExitCode -ne 0) {

                $signatureStatus.Text = "Signature: BASE64 DECODE FAILED"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Base64 decode error=$($DecodeResult.StdErr)"
                )

                $overallStatus.Text = "OVERALL RESULT: ERROR"

                return
            }
        }
        catch {

            $signatureStatus.Text = "Signature: DECODE ERROR"

            Write-Log (
                "Verification ID $VerificationId | " +
                "Base64 decode exception | " +
                "Error=$($_.Exception.Message)"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        # ========================================================
        # STEP 5
        # VERIFY SIGNATURE OF UNCOMPRESSED IMAGE
        # ========================================================

        Write-Log (
            "Verification ID $VerificationId | " +
            "Step 5 | OpenSSL digital signature verification started"
        )

        try {

            # Exact OPNsense workflow:
            #
            # openssl dgst -sha256
            #   -verify <filename>.pub
            #   -signature /tmp/image.sig
            #   <filename>.<image>

            $VerifyResult = Invoke-OpenSSL `
                -OpenSSLPath $OpenSSLPath `
                -Arguments @(
                    "dgst",
                    "-sha256",
                    "-verify",
                    $MirrorPath,
                    "-signature",
                    $DecodedSignature,
                    $UncompressedImage
                )

            Write-Log (
                "Verification ID $VerificationId | " +
                "OpenSSL signature exit code=$($VerifyResult.ExitCode)"
            )

            Write-Log (
                "Verification ID $VerificationId | " +
                "OpenSSL signature output=$($VerifyResult.StdOut)"
            )

            if (-not [string]::IsNullOrWhiteSpace(
                $VerifyResult.StdErr
            )) {

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "OpenSSL signature stderr=$($VerifyResult.StdErr)"
                )
            }

            if (
                ($VerifyResult.ExitCode -eq 0) -and
                ($VerifyResult.StdOut -match "Verified OK")
            ) {

                $signatureStatus.Text = "Signature: VERIFIED OK"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Signature result=VERIFIED OK"
                )
            }
            else {

                $signatureStatus.Text = "Signature: VERIFICATION FAILED"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Signature result=FAILED"
                )

                [System.Windows.Forms.MessageBox]::Show(
                    "OpenSSL did not return 'Verified OK'.`r`n`r`n" +
                    "The image should NOT be considered verified.",
                    "Signature Verification Failed",
                    "OK",
                    "Error"
                )

                $overallStatus.Text = "OVERALL RESULT: NOT VERIFIED"

                return
            }
        }
        catch {

            $signatureStatus.Text = "Signature: ERROR"

            Write-Log (
                "Verification ID $VerificationId | " +
                "Signature verification exception | " +
                "Error=$($_.Exception.Message)"
            )

            $overallStatus.Text = "OVERALL RESULT: ERROR"

            return
        }

        # ========================================================
        # FINAL RESULT
        # ========================================================

        $overallStatus.Text = "OVERALL RESULT: VERIFIED"

        Write-Log (
            "Verification ID $VerificationId | " +
            "OVERALL RESULT=VERIFIED"
        )

        [System.Windows.Forms.MessageBox]::Show(
            "OPNsense image verification completed successfully.`r`n`r`n" +
            "SHA-256: MATCH`r`n" +
            "Public key: MATCH`r`n" +
            "Image unpack: SUCCESS`r`n" +
            "Signature: VERIFIED OK",
            "OPNsense Verification Successful",
            "OK",
            "Information"
        )

        # --------------------------------------------------------
        # Offer to save the verified, uncompressed image somewhere
        # permanent. Up to this point the only copy has lived in
        # the per-run %TEMP% working directory, which the `finally`
        # block below removes regardless of outcome - so without
        # this, a verified image was quietly discarded right after
        # the success dialog closed.
        # --------------------------------------------------------

        $UncompressedImageName = [System.IO.Path]::GetFileName($UncompressedImage)
        $UncompressedExtension = [System.IO.Path]::GetExtension($UncompressedImage)

        $SaveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $SaveDialog.Title = "Save Verified OPNsense Image"
        $SaveDialog.FileName = $UncompressedImageName
        $SaveDialog.OverwritePrompt = $true
        $SaveDialog.AddExtension = $true

        if (-not [string]::IsNullOrWhiteSpace($UncompressedExtension)) {

            $FilterExtension = $UncompressedExtension.TrimStart(".")

            $SaveDialog.Filter = (
                "$($FilterExtension.ToUpper()) image (*.$FilterExtension)|" +
                "*.$FilterExtension|" +
                "All files (*.*)|*.*"
            )
            $SaveDialog.DefaultExt = $FilterExtension
        }
        else {
            $SaveDialog.Filter = "All files (*.*)|*.*"
        }

        # Default to the folder the original .bz2 was picked from,
        # since that's usually where the user is already working.
        $OriginalImageDirectory = Split-Path -Parent $ImagePath

        if (
            (-not [string]::IsNullOrWhiteSpace($OriginalImageDirectory)) -and
            (Test-Path -LiteralPath $OriginalImageDirectory)
        ) {
            $SaveDialog.InitialDirectory = $OriginalImageDirectory
        }

        if ($SaveDialog.ShowDialog() -eq "OK") {

            try {

                Copy-Item `
                    -LiteralPath $UncompressedImage `
                    -Destination $SaveDialog.FileName `
                    -Force `
                    -ErrorAction Stop

                $savedImageStatus.Text = "Saved Image: $($SaveDialog.FileName)"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Verified image saved to $($SaveDialog.FileName)"
                )
            }
            catch {

                $savedImageStatus.Text = "Saved Image: SAVE FAILED"

                Write-Log (
                    "Verification ID $VerificationId | " +
                    "Failed to save verified image | " +
                    "Destination=$($SaveDialog.FileName) | " +
                    "Error=$($_.Exception.Message)"
                )

                [System.Windows.Forms.MessageBox]::Show(
                    "The image was verified successfully, but the " +
                    "verified copy could not be saved to the location " +
                    "you chose.`r`n`r`n" +
                    "$($_.Exception.Message)`r`n`r`n" +
                    "It will still be removed from the temporary " +
                    "working folder when this run finishes.",
                    "Save Failed",
                    "OK",
                    "Warning"
                )
            }
        }
        else {

            $savedImageStatus.Text =
                "Saved Image: (not saved - temporary copy will be removed)"

            Write-Log (
                "Verification ID $VerificationId | " +
                "User did not choose a save location for the verified " +
                "image; it will be removed with the temporary working " +
                "folder"
            )
        }

        # Cleanup of $WorkingDirectory (including $UncompressedImage,
        # whether or not it was also copied out above) happens
        # uniformly in the `finally` block below - on this success
        # path and on every failure path above it, so a failed run
        # never leaves the extracted image sitting in %TEMP%
        # indefinitely.
    }
    finally {

        if ($WorkingDirectory -and (Test-Path -LiteralPath $WorkingDirectory)) {

            Remove-Item `
                -Path $WorkingDirectory `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue

            Write-Log (
                "Verification ID $VerificationId | " +
                "Temporary verification files cleaned up"
            )
        }

        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $verifyButton.Enabled = $true
    }
})

# ============================================================
# FORM CLOSING
# ============================================================

$form.Add_FormClosing({

    Write-Log "Application closing"
})

# ============================================================
# DISPLAY
# ============================================================

[void]$form.ShowDialog()