<#
.SYNOPSIS
  PowerShell companion to iamctl.py: access report and emergency offboarding.
.EXAMPLE
  $env:IAM_BASE_URL = "https://iam.assafwahinc.com"
  ./IamCtl.ps1 -Report -Out access.csv
  $env:IAM_SCIM_TOKEN = "scim_..."
  ./IamCtl.ps1 -Offboard omar.farouk@demo.local
#>
param(
  [switch]$Report,
  [string]$Out = "access.csv",
  [string]$Offboard
)
$Base = if ($env:IAM_BASE_URL) { $env:IAM_BASE_URL.TrimEnd('/') } else { "https://iam.assafwahinc.com" }
$Rest = @{ "X-Actor" = "iamctl.ps1" }

if ($Report) {
  $cat = Invoke-RestMethod "$Base/api/catalog" -Headers $Rest
  $ents = @{}; $cat.entitlements | ForEach-Object { $ents[$_.id] = $_ }
  $sys = @{}; $cat.systems | ForEach-Object { $sys[$_.id] = $_.name }
  $rows = foreach ($p in (Invoke-RestMethod "$Base/api/identities" -Headers $Rest | Where-Object status -eq 'active')) {
    foreach ($g in (Invoke-RestMethod "$Base/api/identities/$($p.id)/access" -Headers $Rest)) {
      $e = $ents[$g.entitlementId]
      $unused = if ($g.lastUsed) { ((Get-Date) - [datetime]$g.lastUsed).Days } else { $null }
      [pscustomobject]@{
        Identity = $p.name; Email = $p.email; System = $sys[$e.systemId]; Entitlement = $e.name
        Privileged = [bool]$e.privileged; Source = $g.source; DaysUnused = $unused
        Flag = if ($e.privileged -and $g.source -ne 'jit') { 'standing-privileged' } elseif ($unused -ge 90) { 'dormant' } else { '' }
      }
    }
  }
  $rows | Export-Csv $Out -NoTypeInformation
  Write-Host "Wrote $($rows.Count) grants to $Out ($(@($rows | Where-Object Flag).Count) flagged)"
}

if ($Offboard) {
  if (-not $env:IAM_SCIM_TOKEN) { throw "Set IAM_SCIM_TOKEN first" }
  $Scim = @{ Authorization = "Bearer $($env:IAM_SCIM_TOKEN)" }
  $filter = [uri]::EscapeDataString("userName eq `"$Offboard`"")
  $u = (Invoke-RestMethod "$Base/scim/v2/Users?filter=$filter" -Headers $Scim).Resources | Select-Object -First 1
  if (-not $u) { throw "No user $Offboard" }
  $body = @{ schemas = @("urn:ietf:params:scim:api:messages:2.0:PatchOp"); Operations = @(@{ op = "replace"; path = "active"; value = $false }) } | ConvertTo-Json -Depth 5
  Invoke-RestMethod "$Base/scim/v2/Users/$($u.id)" -Method Patch -Headers $Scim -ContentType "application/scim+json" -Body $body | Out-Null
  Write-Host "Deactivated $Offboard"
}
