#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (or upgrades) PerfectImage as a Windows service and starts it.

.DESCRIPTION
    - Copies perfectimage.exe to $InstallDir (default C:\Program Files\PerfectImage).
    - Creates %ProgramData%\PerfectImage with an ACL restricted to SYSTEM and
      Administrators (it holds the database, TLS key and DPAPI-protected master key).
    - Seeds config.yaml from config.example.yaml if no config exists, pointing
      data_dir at %ProgramData%\PerfectImage.
    - Registers the "PerfectImage" service via `perfectimage install`, opens the
      firewall port, and starts the service.

.EXAMPLE
    .\scripts\install-windows.ps1 -Binary .\dist\perfectimage-windows-amd64.exe -Port 8443
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,
    [string]$InstallDir = "$env:ProgramFiles\PerfectImage",
    [string]$DataDir = "$env:ProgramData\PerfectImage",
    [string]$ExampleConfig = (Join-Path $PSScriptRoot '..\config.example.yaml'),
    [int]$Port = 8443,
    [switch]$NoFirewall,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$exe = Join-Path $InstallDir 'perfectimage.exe'
$configPath = Join-Path $DataDir 'config.yaml'
$serviceName = 'PerfectImage'
$firewallRule = 'PerfectImage HTTPS'

if ($Uninstall) {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        & $exe uninstall
        if ($LASTEXITCODE -ne 0) { throw "perfectimage uninstall failed ($LASTEXITCODE)" }
    }
    Get-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "Service removed. Data in $DataDir was left in place."
    return
}

if (-not (Test-Path $Binary)) { throw "Binary not found: $Binary" }

# Stop an existing service before replacing the binary.
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host 'Stopping existing service...'
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $Binary $exe

# Data directory locked down to SYSTEM + Administrators (no inheritance).
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {  # LocalSystem, BUILTIN\Administrators
    $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -Path $DataDir -AclObject $acl

if (-not (Test-Path $configPath)) {
    if (-not (Test-Path $ExampleConfig)) { throw "Example config not found: $ExampleConfig" }
    $escaped = $DataDir -replace '\\', '\\'
    (Get-Content -Raw $ExampleConfig) `
        -replace '(?m)^data_dir:.*$', "data_dir: `"$escaped`"" `
        -replace '(?m)^  listen:.*$', "  listen: `":$Port`"" `
        -replace '(?m)^    - \./catalog$', "    - `"$escaped\\catalog`"" |
        Set-Content -Encoding UTF8 -Path $configPath
    Write-Host "Created $configPath - review it before exposing the service."
}

if (-not $existing) {
    & $exe install --config $configPath
    if ($LASTEXITCODE -ne 0) { throw "perfectimage install failed ($LASTEXITCODE)" }
}

if (-not $NoFirewall -and -not (Get-NetFirewallRule -DisplayName $firewallRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $firewallRule -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
}

Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Host "PerfectImage is running: https://$($env:COMPUTERNAME):$Port/"
