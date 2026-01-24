<#
.SYNOPSIS
    Build script for Conch Xbox Live authentication library.

.DESCRIPTION
    Builds the Conch library with configurable options for configuration,
    cleaning, and NuGet package creation.

.PARAMETER Configuration
    Build configuration (Debug or Release). Default is Release.

.PARAMETER Clean
    Remove bin and obj directories before building.

.PARAMETER Pack
    Create a NuGet package after building.

.EXAMPLE
    .\build.ps1
    Builds in Release configuration.

.EXAMPLE
    .\build.ps1 -Configuration Debug -Clean
    Cleans and builds in Debug configuration.

.EXAMPLE
    .\build.ps1 -Pack
    Builds in Release configuration and creates NuGet package.
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [switch]$Clean,

    [switch]$Pack
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$SolutionPath = Join-Path $ProjectRoot "Den.Dev.Conch\Den.Dev.Conch.sln"

# Ensure UTF-8 output for Unicode symbols
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ============================================================================
# TUI Helper Functions
# ============================================================================

# Unicode characters for TUI
$script:Chars = @{
    TopLeft     = [char]0x250C      # box top left
    TopRight    = [char]0x2510      # box top right
    BottomLeft  = [char]0x2514      # box bottom left
    BottomRight = [char]0x2518      # box bottom right
    Horizontal  = [char]0x2500      # horizontal line
    Vertical    = [char]0x2502      # vertical line
    Bullet      = [char]0x25CB      # hollow circle
    Check       = [char]0x2713      # checkmark
    Cross       = [char]0x2717      # x mark
    Arrow       = [char]0x203A      # single arrow
    Spinner     = @(
        [char]0x280B,  # braille dots
        [char]0x2819,
        [char]0x2839,
        [char]0x2838,
        [char]0x283C,
        [char]0x2834,
        [char]0x2826,
        [char]0x2827,
        [char]0x2807,
        [char]0x280F
    )
}

$script:SpinnerIndex = 0

function Get-Timestamp {
    return (Get-Date).ToString("HH:mm:ss")
}

function Write-Header {
    $title = "Conch Build Script"
    $h = $script:Chars.Horizontal
    $border = "$h" * 50

    Write-Host ""
    Write-Host "  $($script:Chars.TopLeft)$border$($script:Chars.TopRight)" -ForegroundColor DarkGray
    Write-Host "  $($script:Chars.Vertical)" -ForegroundColor DarkGray -NoNewline
    Write-Host "  $title".PadRight(50) -ForegroundColor Cyan -NoNewline
    Write-Host "$($script:Chars.Vertical)" -ForegroundColor DarkGray
    Write-Host "  $($script:Chars.BottomLeft)$border$($script:Chars.BottomRight)" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-TaskStart {
    param([string]$Message)

    Write-Host "  $($script:Chars.Bullet) " -ForegroundColor DarkGray -NoNewline
    Write-Host "$Message" -ForegroundColor White -NoNewline
    Write-Host " " -NoNewline
}

function Write-TaskProgress {
    param([string]$Message)

    $frame = $script:Chars.Spinner[$script:SpinnerIndex]
    $script:SpinnerIndex = ($script:SpinnerIndex + 1) % $script:Chars.Spinner.Count

    Write-Host "`r  " -NoNewline
    Write-Host "$frame " -ForegroundColor Cyan -NoNewline
    Write-Host "$Message" -ForegroundColor Gray -NoNewline
    Write-Host (" " * 20) -NoNewline
}

function Write-TaskSuccess {
    param([string]$Message, [string]$Duration = "")

    Write-Host "`r  " -NoNewline
    Write-Host "$($script:Chars.Check) " -ForegroundColor Green -NoNewline
    Write-Host "$Message" -ForegroundColor White -NoNewline
    if ($Duration) {
        Write-Host " ($Duration)" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
}

function Write-TaskError {
    param([string]$Message)

    Write-Host "`r  " -NoNewline
    Write-Host "$($script:Chars.Cross) " -ForegroundColor Red -NoNewline
    Write-Host "$Message" -ForegroundColor White
}

function Write-TaskSkipped {
    param([string]$Message)

    Write-Host "  $($script:Chars.Bullet) " -ForegroundColor DarkGray -NoNewline
    Write-Host "$Message" -ForegroundColor DarkGray -NoNewline
    Write-Host " (skipped)" -ForegroundColor DarkGray
}

function Write-SubTask {
    param([string]$Message, [switch]$Success, [switch]$Error)

    Write-Host "    " -NoNewline
    if ($Success) {
        Write-Host "$($script:Chars.Arrow) " -ForegroundColor DarkGray -NoNewline
        Write-Host "$Message" -ForegroundColor Gray
    } elseif ($Error) {
        Write-Host "$($script:Chars.Arrow) " -ForegroundColor Red -NoNewline
        Write-Host "$Message" -ForegroundColor Gray
    } else {
        Write-Host "$($script:Chars.Arrow) " -ForegroundColor DarkGray -NoNewline
        Write-Host "$Message" -ForegroundColor DarkGray
    }
}

function Write-Section {
    param([string]$Title)

    $h = $script:Chars.Horizontal
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  $("$h" * $Title.Length)" -ForegroundColor DarkGray
}

function Write-Summary {
    param(
        [bool]$Success,
        [string]$Configuration,
        [bool]$PackageCreated,
        [string]$TotalDuration
    )

    Write-Host ""
    $h = $script:Chars.Horizontal
    $border = "$h" * 50

    if ($Success) {
        Write-Host "  $($script:Chars.TopLeft)$border$($script:Chars.TopRight)" -ForegroundColor DarkGray
        Write-Host "  $($script:Chars.Vertical)" -ForegroundColor DarkGray -NoNewline
        $msg = "  $($script:Chars.Check) Build completed successfully"
        Write-Host $msg.PadRight(50) -ForegroundColor Green -NoNewline
        Write-Host "$($script:Chars.Vertical)" -ForegroundColor DarkGray
        Write-Host "  $($script:Chars.BottomLeft)$border$($script:Chars.BottomRight)" -ForegroundColor DarkGray
    } else {
        Write-Host "  $($script:Chars.TopLeft)$border$($script:Chars.TopRight)" -ForegroundColor DarkGray
        Write-Host "  $($script:Chars.Vertical)" -ForegroundColor DarkGray -NoNewline
        $msg = "  $($script:Chars.Cross) Build failed"
        Write-Host $msg.PadRight(50) -ForegroundColor Red -NoNewline
        Write-Host "$($script:Chars.Vertical)" -ForegroundColor DarkGray
        Write-Host "  $($script:Chars.BottomLeft)$border$($script:Chars.BottomRight)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "    Configuration:  " -ForegroundColor DarkGray -NoNewline
    Write-Host "$Configuration" -ForegroundColor White
    Write-Host "    Duration:       " -ForegroundColor DarkGray -NoNewline
    Write-Host "$TotalDuration" -ForegroundColor White
    if ($PackageCreated) {
        Write-Host "    Package:        " -ForegroundColor DarkGray -NoNewline
        Write-Host "Created" -ForegroundColor Green
    }
    Write-Host ""
}

function Format-Duration {
    param([TimeSpan]$Duration)

    if ($Duration.TotalSeconds -lt 1) {
        return "{0:N0}ms" -f $Duration.TotalMilliseconds
    } elseif ($Duration.TotalMinutes -lt 1) {
        return "{0:N1}s" -f $Duration.TotalSeconds
    } else {
        return "{0:N0}m {1:N0}s" -f [Math]::Floor($Duration.TotalMinutes), $Duration.Seconds
    }
}

# ============================================================================
# Build Steps
# ============================================================================

$buildSuccess = $true
$packageCreated = $false
$totalStart = Get-Date

Write-Header

# --- Clean Step ---
Write-Section "Clean"

if ($Clean) {
    $cleanStart = Get-Date
    Write-TaskStart "Removing build artifacts"

    try {
        $dirsToClean = Get-ChildItem -Path (Join-Path $ProjectRoot "Den.Dev.Conch") -Recurse -Directory |
            Where-Object { $_.Name -eq "bin" -or $_.Name -eq "obj" }

        $count = 0
        foreach ($dir in $dirsToClean) {
            Remove-Item -Path $dir.FullName -Recurse -Force
            $count++
        }

        $cleanDuration = Format-Duration ((Get-Date) - $cleanStart)
        Write-TaskSuccess -Message "Removed $count directories" -Duration $cleanDuration
    }
    catch {
        Write-TaskError "Failed to clean directories"
        Write-SubTask -Message $_.Exception.Message -Error
        $buildSuccess = $false
    }
} else {
    Write-TaskSkipped "Clean build artifacts"
}

# --- Restore Step ---
Write-Section "Restore"

$restoreStart = Get-Date
Write-TaskStart "Restoring dependencies"

$restoreOutput = & dotnet restore $SolutionPath 2>&1
if ($LASTEXITCODE -eq 0) {
    $restoreDuration = Format-Duration ((Get-Date) - $restoreStart)
    Write-TaskSuccess -Message "Dependencies restored" -Duration $restoreDuration
} else {
    Write-TaskError "Failed to restore dependencies"
    $restoreOutput | ForEach-Object { Write-SubTask -Message $_ -Error }
    $buildSuccess = $false
}

# --- Build Step ---
if ($buildSuccess) {
    Write-Section "Build"

    $buildStart = Get-Date
    Write-TaskStart "Compiling ($Configuration)"

    $buildOutput = & dotnet build $SolutionPath -c $Configuration --no-restore -warnaserror 2>&1

    if ($LASTEXITCODE -eq 0) {
        $buildDuration = Format-Duration ((Get-Date) - $buildStart)
        Write-TaskSuccess -Message "Build succeeded - 0 warnings, 0 errors" -Duration $buildDuration

        # Show output assembly
        $outputDll = Join-Path $ProjectRoot "Den.Dev.Conch\Den.Dev.Conch\bin\$Configuration\net10.0\Den.Dev.Conch.dll"
        if (Test-Path $outputDll) {
            $dllSize = [math]::Round((Get-Item $outputDll).Length / 1KB, 0)
            Write-SubTask -Message "Output: Den.Dev.Conch.dll ($dllSize KB)" -Success
        }
    } else {
        Write-TaskError "Build failed"
        $buildOutput | Where-Object { $_ -match "error|warning" } | ForEach-Object {
            Write-SubTask -Message $_ -Error
        }
        $buildSuccess = $false
    }
}

# --- Pack Step ---
if ($buildSuccess) {
    Write-Section "Package"

    if ($Pack) {
        $packStart = Get-Date
        Write-TaskStart "Creating NuGet package"

        $packOutput = & dotnet pack $SolutionPath -c $Configuration --no-build 2>&1

        if ($LASTEXITCODE -eq 0) {
            $packDuration = Format-Duration ((Get-Date) - $packStart)
            Write-TaskSuccess -Message "Package created" -Duration $packDuration
            $packageCreated = $true

            # Show package path
            $nupkg = Get-ChildItem -Path (Join-Path $ProjectRoot "Den.Dev.Conch\Den.Dev.Conch\bin\$Configuration") -Filter "*.nupkg" | Select-Object -First 1
            if ($nupkg) {
                $pkgSize = [math]::Round($nupkg.Length / 1KB, 0)
                Write-SubTask -Message "$($nupkg.Name) ($pkgSize KB)" -Success
            }
        } else {
            Write-TaskError "Failed to create package"
            $packOutput | Where-Object { $_ -match "error" } | ForEach-Object {
                Write-SubTask -Message $_ -Error
            }
            $buildSuccess = $false
        }
    } else {
        Write-TaskSkipped "Create NuGet package"
    }
}

# --- Summary ---
$totalDuration = Format-Duration ((Get-Date) - $totalStart)
Write-Summary -Success $buildSuccess -Configuration $Configuration -PackageCreated $packageCreated -TotalDuration $totalDuration

if ($buildSuccess) {
    exit 0
} else {
    exit 1
}
