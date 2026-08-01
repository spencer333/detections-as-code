<#
.SYNOPSIS  Compute the detection-coverage benchmark from detection_coverage.json.
.EXAMPLE   powershell -File .\run_coverage.ps1
#>
param([string]$Json = "$PSScriptRoot\detection_coverage.json")
$d = Get-Content $Json -Raw | ConvertFrom-Json
$rules = $d.rules
$total = $rules.Count
$val = @($rules | Where-Object { $_.validated }).Count
$rulePct = [math]::Round(100 * $val / $total)

$covered = @{}
foreach ($r in $rules) { if ($r.validated) { foreach ($t in $r.techniques) { $covered[$t] = $true } } }
$inScope = $d.in_scope_techniques
$tcov = @($inScope | Where-Object { $covered[$_] }).Count
$tPct = [math]::Round(100 * $tcov / $inScope.Count)

Write-Host "Detection-coverage benchmark ($($d.generated))" -ForegroundColor Cyan
Write-Host "  Corpus:          $($d.corpus)"
Write-Host "  False positives: $($d.false_positives) across $($d.samples_tested) samples"
Write-Host "  Rules validated: $val / $total ($rulePct%)" -ForegroundColor Green
Write-Host "  Techniques with a validated rule: $tcov / $($inScope.Count) ($tPct%)" -ForegroundColor Green
$ut = @($rules | Where-Object { $_.unit_tested }).Count
$utPct = [math]::Round(100 * $ut / $total)
Write-Host "  Rules unit-tested (logic proven on the documented IOC + benign near-miss): $ut / $total ($utPct%)" -ForegroundColor Green
Write-Host "  (unit-tested = rule logic is correct; validated = fired on REAL attack telemetry. Different, both matter.)" -ForegroundColor DarkGray
Write-Host "`n  Backlog (rules not yet validated against REAL telemetry - what A5 moves):" -ForegroundColor Yellow
$rules | Where-Object { -not $_.validated } | ForEach-Object {
  Write-Host ("   - {0}  [{1}]" -f $_.rule, ($_.techniques -join ','))
}
