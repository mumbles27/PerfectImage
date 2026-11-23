<#
  Base configuration, run over WinRM after Windows is installed.
#>
$ErrorActionPreference = 'Stop'

Write-Host '==> High performance power plan'
powercfg /setactive SCHEME_MIN
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0

Write-Host '==> Disabling hibernation'
powercfg /hibernate off

Write-Host '==> Ensuring the QEMU guest agent is running'
Set-Service -Name QEMU-GA -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name QEMU-GA -ErrorAction SilentlyContinue
