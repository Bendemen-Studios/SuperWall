param([string]$Pin)
if ([string]::IsNullOrWhiteSpace($Pin)) { $Pin = Read-Host 'Super Wall download PIN' }
try {
  $body = @{ pin = $Pin } | ConvertTo-Json
  $r = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:18581/unlock' -ContentType 'application/json' -Body $body
  Write-Host $r.message
} catch { Write-Host 'Download unlock failed.' -ForegroundColor Red }
