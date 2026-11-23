<#
  Shrink and sanitize the image before sysprep.
#>
$ErrorActionPreference = 'Continue'

Write-Host '==> Removing cached answer files (they contain the build password)'
Remove-Item -Force -ErrorAction SilentlyContinue `
    "$env:SystemRoot\Panther\unattend.xml", "$env:SystemRoot\Panther\autounattend.xml", `
    "$env:SystemRoot\Panther\Unattend\unattend.xml", "$env:SystemRoot\Panther\Unattend\autounattend.xml", `
    "$env:SystemRoot\System32\Sysprep\unattend.xml", 'C:\unattend.xml', 'C:\autounattend.xml'

Write-Host '==> Removing AutoLogon credentials'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($n in 'DefaultPassword', 'AutoAdminLogon', 'AutoLogonCount') {
    Remove-ItemProperty -Path $wl -Name $n -ErrorAction SilentlyContinue
}

Write-Host '==> Clearing temporary files'
Get-ChildItem "$env:SystemRoot\Temp", $env:TEMP -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike 'pi-*.log' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host '==> Component store cleanup'
Dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Host

Write-Host '==> Clearing event logs'
wevtutil.exe el | ForEach-Object { wevtutil.exe cl $_ 2>$null }

Write-Host '==> Trimming free space'
Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue
exit 0
