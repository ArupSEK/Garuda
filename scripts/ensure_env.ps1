[CmdletBinding()]
param(
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
else {
    $ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
}

$ExampleFile = Join-Path $ProjectRoot ".env.example"
$EnvFile = Join-Path $ProjectRoot ".env"

if (-not (Test-Path -LiteralPath $ExampleFile)) {
    throw "Missing environment template: $ExampleFile"
}

$Created = -not (Test-Path -LiteralPath $EnvFile)
if ($Created) {
    $Content = [System.IO.File]::ReadAllText($ExampleFile)
}
else {
    $Content = [System.IO.File]::ReadAllText($EnvFile)
}

$SecretPattern = [System.Text.RegularExpressions.Regex]::new(
    '(?m)^SECRET_KEY[ \t]*=[ \t]*(.*?)[ \t]*\r?$'
)
$SecretMatches = $SecretPattern.Matches($Content)
$CurrentSecret = ""
if ($SecretMatches.Count -gt 0) {
    $CurrentSecret = $SecretMatches[$SecretMatches.Count - 1].Groups[1].Value.Trim()
}

$NeedsSecret = (
    $SecretMatches.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace($CurrentSecret) -or
    $CurrentSecret -eq "replace-with-a-long-random-secret" -or
    $CurrentSecret.Length -lt 32
)

if ($NeedsSecret) {
    $Bytes = New-Object byte[] 48
    $Generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Generator.GetBytes($Bytes)
    }
    finally {
        $Generator.Dispose()
    }
    $Secret = ([System.BitConverter]::ToString($Bytes)).Replace("-", "").ToLowerInvariant()

    # Remove duplicate or malformed entries and append one canonical value.
    $Content = $SecretPattern.Replace($Content, "").TrimEnd([char[]]"`r`n")
    $Content += [Environment]::NewLine + "SECRET_KEY=$Secret" + [Environment]::NewLine

    $Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($EnvFile, $Content, $Utf8WithoutBom)

    if ($Created) {
        Write-Host "Created .env with a secure application secret."
    }
    else {
        Write-Host "Repaired the missing or invalid SECRET_KEY in .env."
    }
}
elseif ($Created) {
    # This branch is defensive in case the template later ships with a valid secret.
    $Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($EnvFile, $Content, $Utf8WithoutBom)
    Write-Host "Created .env."
}
