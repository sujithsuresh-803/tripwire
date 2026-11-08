<#
.SYNOPSIS
  L3 containment from a terminal or a SOAR playbook: quarantine or release an agent, flip the kill switch,
  or list the agent inventory with blast radius.
.EXAMPLE
  ./Invoke-TripwireContainment.ps1 -Gateway https://tripwire.internal -Action Quarantine -AgentId sales-flow-bot
  ./Invoke-TripwireContainment.ps1 -Gateway https://tripwire.internal -Action Inventory
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $Gateway,
    [Parameter(Mandatory)] [ValidateSet('Quarantine', 'Release', 'KillOn', 'KillOff', 'Inventory')] [string] $Action,
    [string] $AgentId,
    [string] $Token = $env:TRIPWIRE_ADMIN_TOKEN
)
$ErrorActionPreference = 'Stop'
if (-not $Token) { throw 'Set TRIPWIRE_ADMIN_TOKEN or pass -Token.' }
if ($Action -in 'Quarantine', 'Release' -and -not $AgentId) { throw "-AgentId is required for $Action." }
$headers = @{ 'X-Admin-Token' = $Token }
$base = $Gateway.TrimEnd('/')

switch ($Action) {
    'Inventory' {
        Invoke-RestMethod -Method Get -Uri "$base/v1/admin/inventory" -Headers $headers |
            Sort-Object blast_radius, agent | Format-Table agent, owner, profile, blast_radius, status, recent_strikes
    }
    { $_ -in 'Quarantine', 'Release' } {
        if ($PSCmdlet.ShouldProcess($AgentId, $Action)) {
            $start = Get-Date
            $r = Invoke-RestMethod -Method Post -Uri "$base/v1/admin/agents/$AgentId/$($Action.ToLower())" -Headers $headers
            '{0} -> {1} in {2:N0} ms' -f $r.agent, $r.status, ((Get-Date) - $start).TotalMilliseconds
        }
    }
    { $_ -in 'KillOn', 'KillOff' } {
        if ($PSCmdlet.ShouldProcess('all agents', $Action)) {
            $body = @{ on = ($Action -eq 'KillOn') } | ConvertTo-Json
            $r = Invoke-RestMethod -Method Post -Uri "$base/v1/admin/kill-switch" -Headers $headers -Body $body -ContentType 'application/json'
            "kill switch: $($r.kill_switch)"
        }
    }
}
