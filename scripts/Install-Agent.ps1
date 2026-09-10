param(
  [Parameter(Mandatory=$true)][string]$DashboardUrl,
  [Parameter(Mandatory=$true)][string]$EnrollmentKey
)
$ErrorActionPreference='Stop'
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root 'publish\agent'
if (!(Test-Path $publish)) { throw "Publish directory not found. Run: dotnet publish src\SuperWall.Agent -c Release -r win-x64 --self-contained false -o publish\agent" }
$state = "$env:ProgramData\SuperWall"
New-Item -ItemType Directory -Force $state | Out-Null
$env:SUPERWALL_DASHBOARD=$DashboardUrl
[Environment]::SetEnvironmentVariable('SUPERWALL_DASHBOARD',$DashboardUrl,'Machine')
$enrollmentFile = Join-Path $state 'enrollment.key'
Set-Content -Path $enrollmentFile -Value $EnrollmentKey -NoNewline
icacls.exe $enrollmentFile /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
$agent = Join-Path $publish 'SuperWall.Agent.exe'
$service = Get-Service -Name SuperWallAgent -ErrorAction SilentlyContinue
if ($service) { Stop-Service SuperWallAgent -Force -ErrorAction SilentlyContinue; sc.exe delete SuperWallAgent | Out-Null; Start-Sleep 1 }
sc.exe create SuperWallAgent binPath= "`"$agent`"" start= auto obj= LocalSystem DisplayName= "SuperWall Agent" | Out-Null
sc.exe description SuperWallAgent "Super Wall offline-first parental control agent" | Out-Null
sc.exe failure SuperWallAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service SuperWallAgent
Write-Host "SuperWall Agent installed and started. Enrollment key is ACL-protected and will be consumed after successful enrollment."