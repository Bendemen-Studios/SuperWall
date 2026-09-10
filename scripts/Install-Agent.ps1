param(
  [Parameter(Mandatory=$true)][string]$DashboardUrl,
  [Parameter(Mandatory=$true)][string]$AgentToken
)
$ErrorActionPreference='Stop'
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root 'publish\agent'
if (!(Test-Path $publish)) { throw "Publish directory not found. Run: dotnet publish src\SuperWall.Agent -c Release -r win-x64 --self-contained false -o publish\agent" }
New-Item -ItemType Directory -Force "$env:ProgramData\SuperWall" | Out-Null
$env:SUPERWALL_DASHBOARD=$DashboardUrl
$env:SUPERWALL_AGENT_TOKEN=$AgentToken
$agent = Join-Path $publish 'SuperWall.Agent.exe'
& $agent --install-config 2>$null
$service = Get-Service -Name SuperWallAgent -ErrorAction SilentlyContinue
if ($service) { sc.exe stop SuperWallAgent | Out-Null; sc.exe delete SuperWallAgent | Out-Null; Start-Sleep 1 }
sc.exe create SuperWallAgent binPath= "`"$agent`"" start= auto DisplayName= "SuperWall Agent" | Out-Null
sc.exe description SuperWallAgent "Super Wall offline-first parental control agent" | Out-Null
[Environment]::SetEnvironmentVariable('SUPERWALL_DASHBOARD',$DashboardUrl,'Machine')
[Environment]::SetEnvironmentVariable('SUPERWALL_AGENT_TOKEN',$AgentToken,'Machine')
Start-Service SuperWallAgent
Write-Host "SuperWall Agent installed and started."