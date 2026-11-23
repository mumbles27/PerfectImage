<#
  Generalize the VM with Sysprep (/mode:vm, suitable for Proxmox). The build
  user's password is not stored in the generalize answer file; the deploy
  step resets the administrator password through the QEMU guest agent.
  Must be the last provisioner: it leaves the VM generalized and running
  until Packer shuts it down and converts it to a template.
#>
$ErrorActionPreference = 'Stop'

$unattend = 'C:\Windows\Panther\unattend-generalize.xml'
New-Item -ItemType Directory -Path (Split-Path $unattend) -Force | Out-Null

@'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <!-- Remove the build-time WinRM listener and firewall rule from deployed clones. -->
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Path>cmd.exe /c winrm delete winrm/config/Listener?Address=*+Transport=HTTPS</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>2</Order>
          <Path>cmd.exe /c netsh advfirewall firewall delete rule name="PerfectImage WinRM HTTPS"</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Work</NetworkLocation>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
      </OOBE>
    </component>
  </settings>
</unattend>
'@ | Set-Content -Path $unattend -Encoding UTF8

# Sysprep refuses to run while these are in a bad state.
Stop-Service -Name WMPNetworkSvc -ErrorAction SilentlyContinue

Write-Host '==> Running sysprep /generalize /oobe /quit /mode:vm'
$p = Start-Process -FilePath "$env:SystemRoot\System32\Sysprep\Sysprep.exe" -Wait -PassThru -ArgumentList `
    '/generalize', '/oobe', '/quit', '/mode:vm', "/unattend:$unattend"
if ($p.ExitCode -ne 0) { throw "sysprep exited with code $($p.ExitCode); see $env:SystemRoot\System32\Sysprep\Panther\setuperr.log" }

Write-Host '==> Waiting for generalization to finish'
$deadline = (Get-Date).AddMinutes(30)
while ((Get-Date) -lt $deadline) {
    $gen = (Get-ItemProperty 'HKLM:\SYSTEM\Setup\Status\SysprepStatus' -ErrorAction SilentlyContinue).GeneralizationState
    $img = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction SilentlyContinue).ImageState
    if ($gen -eq 7 -or $img -eq 'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE') {
        Write-Host "Generalized (GeneralizationState=$gen, ImageState=$img)"
        exit 0
    }
    Start-Sleep -Seconds 5
}
throw 'Timed out waiting for sysprep to finish generalizing'
