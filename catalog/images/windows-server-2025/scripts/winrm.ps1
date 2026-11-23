<#
  Configure WinRM over HTTPS (port 5986, self-signed certificate, Basic auth)
  so Packer can connect. Runs at first logon from the PIUNATTEND CD.
  The listener and firewall rule are removed again when the image is
  generalized (see scripts/sysprep.ps1).
#>
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:SystemRoot\Temp\pi-winrm.log" -Append | Out-Null

# WinRM refuses to start on Public networks.
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Local (non-built-in) administrators need this to get an elevated remote token.
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord -Force

# Replace the default listeners with a single HTTPS listener.
Get-ChildItem WSMan:\localhost\Listener | Remove-Item -Recurse -Force
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(5)
New-WSManInstance -ResourceURI winrm/config/Listener `
    -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } `
    -ValueSet @{ Hostname = $env:COMPUTERNAME; CertificateThumbprint = $cert.Thumbprint } | Out-Null

Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 2048
Set-Item WSMan:\localhost\Shell\MaxProcessesPerShell -Value 100
Set-Item WSMan:\localhost\MaxTimeoutms -Value 1800000

# Firewall: allow 5986, close the plain-HTTP rule.
Disable-NetFirewallRule -Name 'WINRM-HTTP-In-TCP', 'WINRM-HTTP-In-TCP-PUBLIC' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'PerfectImage-WinRM-HTTPS' -DisplayName 'PerfectImage WinRM HTTPS' `
    -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Any | Out-Null

Set-Service -Name WinRM -StartupType Automatic
Restart-Service -Name WinRM
Stop-Transcript | Out-Null
