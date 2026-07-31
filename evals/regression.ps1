param([Parameter(Mandatory=$true)][string]$EvtxDir)
$ErrorActionPreference = 'Stop'
function Get-Events($path) {
  Get-WinEvent -Path $path -ErrorAction Stop | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
    [pscustomobject]@{ Id=[int]$_.Id; Image=$d['Image']; CommandLine=$d['CommandLine']; ParentImage=$d['ParentImage']; TargetObject=$d['TargetObject']; TargetFilename=$d['TargetFilename']; Details=$d['Details'] }
  }
}
function has($s,$sub){ $s -and ($s.ToLower().Contains($sub.ToLower())) }
$rules = [ordered]@{
 'akira_lsass_comsvcs_minidump'    = { param($e) [bool]($e | ?{ $_.Id -eq 1 -and (has $_.CommandLine 'comsvcs.dll') -and (has $_.CommandLine 'minidump') } | select -First 1) }
 'akira_vss_shadow_delete_wmi'     = { param($e) [bool]($e | ?{ $_.Id -eq 1 -and (((has $_.CommandLine 'win32_shadowcopy') -and (has $_.CommandLine 'remove-wmiobject')) -or ((has $_.CommandLine 'shadowcopy') -and (has $_.CommandLine 'delete'))) } | select -First 1) }
 'interlock_rundll32_wasd'         = { param($e) [bool]($e | ?{ $_.Id -eq 1 -and (has $_.Image 'rundll32.exe') -and (has $_.CommandLine '.wasd') } | select -First 1) }
 'interlock_chrome_updater_runkey' = { param($e) [bool]($e | ?{ $_.Id -eq 13 -and ((has $_.TargetObject '\currentversion\run\') -or (has $_.TargetObject '\currentversion\runonce\')) -and ($_.TargetObject -and $_.TargetObject.ToLower().TrimEnd().EndsWith('chrome updater')) } | select -First 1) }
 'play_tooling_in_public_music'    = { param($e) [bool]($e | ?{ ($_.Id -eq 1 -and ((has $_.Image '\users\public\music\') -or (has $_.ParentImage '\users\public\music\'))) -or ($_.Id -eq 11 -and (has $_.TargetFilename '\users\public\music\')) } | select -First 1) }
 'medusa_rdp_fDenyTSConnections'   = { param($e) [bool]($e | ?{ $_.Id -eq 1 -and (has $_.CommandLine 'fdenytsconnections') -and (has $_.CommandLine '/d 0') } | select -First 1) }
 'medusa_netsh_3389'               = { param($e) [bool]($e | ?{ $_.Id -eq 1 -and (has $_.Image 'netsh.exe') -and (has $_.CommandLine 'firewall') -and (has $_.CommandLine '3389') -and (has $_.CommandLine 'allow') } | select -First 1) }
 'rdp_registry_enable_tamper'      = { param($e) [bool]($e | ?{ $_.Id -eq 13 -and ( (($_.TargetObject -and $_.TargetObject.ToLower().EndsWith('\control\terminal server\fdenytsconnections')) -and (has $_.Details 'dword (0x00000000)')) -or (($_.TargetObject -and $_.TargetObject.ToLower().EndsWith('\services\termservice\parameters\servicedll')) -and -not (has $_.Details 'termsrv.dll')) -or ($_.TargetObject -and $_.TargetObject.ToLower().EndsWith('\terminal server\winstations\rdp-tcp\portnumber')) ) } | select -First 1) }
}
$files = Get-ChildItem $EvtxDir -Filter *.evtx | Sort-Object Name
$fire = @{}; foreach ($rn in $rules.Keys) { $fire[$rn] = @() }
Write-Host ("{0,-22} {1,-5} {2}" -f 'SAMPLE','EVTS','RULES FIRED')
Write-Host ('-'*70)
foreach ($f in $files) {
  $ev = @(Get-Events $f.FullName)
  $hits = @(); foreach ($rn in $rules.Keys) { if (& $rules[$rn] $ev) { $hits += $rn; $fire[$rn] += $f.BaseName } }
  $lbl = if ($hits) { $hits -join ', ' } else { '(clean)' }
  $color = if ($hits) { 'Yellow' } else { 'DarkGray' }
  Write-Host ("{0,-22} {1,-5} {2}" -f $f.BaseName, $ev.Count, $lbl) -ForegroundColor $color
}
Write-Host ("`n=== per-rule fire counts across {0} samples ===" -f $files.Count) -ForegroundColor Cyan
foreach ($rn in $rules.Keys) {
  $n = $fire[$rn].Count
  Write-Host ("{0,-34} {1}  {2}" -f $rn, $n, ($(if($n){'-> '+($fire[$rn] -join ', ')}else{''})))
}