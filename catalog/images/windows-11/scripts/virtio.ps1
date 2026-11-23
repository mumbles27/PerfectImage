<#
  Install the virtio-win drivers and the QEMU guest agent.
  Runs at first logon from the PIUNATTEND CD. The virtio-win ISO is located
  by looking for its guest-tools installer on every CD-ROM drive.
#>
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemRoot\Temp\pi-virtio.log" -Append | Out-Null

$root = $null
foreach ($v in Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'CD-ROM' }) {
    $r = "$($v.DriveLetter):\"
    if ((Test-Path "$r\virtio-win-gt-x64.msi") -or (Test-Path "$r\virtio-win-guest-tools.exe")) { $root = $r; break }
}
if (-not $root) { throw 'virtio-win ISO not found on any CD-ROM drive' }
Write-Host "virtio-win media: $root"

function Install-Msi($path) {
    Write-Host "Installing $path"
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$path`" /qn /norestart" -Wait -PassThru
    # 0 = success, 3010 = success (reboot required)
    if ($p.ExitCode -notin 0, 3010) { throw "msiexec failed for $path with exit code $($p.ExitCode)" }
}

if (Test-Path "$root\virtio-win-gt-x64.msi") {
    Install-Msi "$root\virtio-win-gt-x64.msi"
} else {
    $p = Start-Process "$root\virtio-win-guest-tools.exe" -ArgumentList '/quiet /norestart' -Wait -PassThru
    if ($p.ExitCode -notin 0, 3010) { throw "virtio-win-guest-tools.exe failed with exit code $($p.ExitCode)" }
}

$ga = "$root\guest-agent\qemu-ga-x86_64.msi"
if (Test-Path $ga) { Install-Msi $ga } else { Write-Host 'Guest agent MSI not found; assuming the guest-tools installer included it.' }

Set-Service -Name QEMU-GA -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name QEMU-GA -ErrorAction SilentlyContinue
Stop-Transcript | Out-Null
