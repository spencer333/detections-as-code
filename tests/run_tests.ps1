<#
.SYNOPSIS  Detection unit tests: each rule must FIRE on its advisory-documented IOC (positive) and
           stay SILENT on a benign near-miss (negative). Proves rule logic without needing telemetry.
.NOTES     This is NOT the same as real-telemetry validation (see evals/). It is a logic/regression
           test: does the rule match the exact behavior the advisory describes, and only that?
.EXAMPLE   powershell -File .\run_tests.ps1
#>
$ErrorActionPreference = 'Stop'
function has($s,$sub){ $s -and ($s.ToLower().Contains($sub.ToLower())) }
function ev($h){ $o=[pscustomobject]@{Id=0;Image='';CommandLine='';ParentImage='';TargetObject='';TargetFilename='';Details=''}; $h.GetEnumerator()|%{ $o.$($_.Key)=$_.Value }; $o }

# Predicates mirror rules/ (kept in sync with evals/regression.ps1).
$rules = [ordered]@{
 'akira_lsass_comsvcs_minidump'    = { param($e) (has $e.CommandLine 'comsvcs.dll') -and (has $e.CommandLine 'minidump') -and $e.Id -eq 1 }
 'akira_vss_shadow_delete_wmi'     = { param($e) $e.Id -eq 1 -and (((has $e.CommandLine 'win32_shadowcopy') -and (has $e.CommandLine 'remove-wmiobject')) -or ((has $e.CommandLine 'shadowcopy') -and (has $e.CommandLine 'delete'))) }
 'interlock_rundll32_wasd_cleanup' = { param($e) $e.Id -eq 1 -and (has $e.Image 'rundll32.exe') -and (has $e.CommandLine '.wasd') }
 'interlock_chrome_updater_runkey' = { param($e) $e.Id -eq 13 -and ((has $e.TargetObject '\currentversion\run\') -or (has $e.TargetObject '\currentversion\runonce\')) -and ($e.TargetObject.ToLower().TrimEnd().EndsWith('chrome updater')) }
 'play_tooling_in_public_music_exec' = { param($e) $e.Id -eq 1 -and ((has $e.Image '\users\public\music\') -or (has $e.ParentImage '\users\public\music\')) }
 'play_tooling_in_public_music_note' = { param($e) $e.Id -eq 11 -and (has $e.TargetFilename '\users\public\music\') -and $e.TargetFilename.ToLower().EndsWith('readme.txt') }
 'medusa_openrdp_fDenyTSConnections' = { param($e) $e.Id -eq 1 -and (has $e.CommandLine 'fdenytsconnections') -and (has $e.CommandLine '/d 0') }
 'medusa_openrdp_netsh_3389'       = { param($e) $e.Id -eq 1 -and (has $e.Image 'netsh.exe') -and (has $e.CommandLine 'firewall') -and (has $e.CommandLine '3389') -and (has $e.CommandLine 'allow') }
 'rdp_registry_enable_tamper'      = { param($e) $e.Id -eq 13 -and ( ((has $e.TargetObject 'terminal server\fdenytsconnections') -and (has $e.Details '0x00000000')) -or ($e.TargetObject.ToLower().EndsWith('\rdp-tcp\portnumber')) -or ((has $e.TargetObject 'termservice\parameters\servicedll') -and -not (has $e.Details 'termsrv.dll')) ) }
 'ghost_disable_defender_setmppreference' = { param($e) $e.Id -eq 1 -and (has $e.CommandLine 'set-mppreference') -and ((has $e.CommandLine '-disablerealtimemonitoring 1') -or (has $e.CommandLine '-disablebehaviormonitoring 1') -or (has $e.CommandLine '-disableioavprotection 1') -or (has $e.CommandLine '-mapsreporting disabled') -or (has $e.CommandLine '-submitsamplesconsent neversend')) }
}

# positive = advisory-documented IOC (must fire); negative = benign near-miss (must NOT fire)
$cases = @(
 @{ r='akira_lsass_comsvcs_minidump'; p=(ev @{Id=1;CommandLine='rundll32 C:\windows\system32\comsvcs.dll, MiniDump 640 C:\t.dmp full'}); n=(ev @{Id=1;CommandLine='rundll32 shell32.dll,Control_RunDLL'}) }
 @{ r='akira_vss_shadow_delete_wmi'; p=(ev @{Id=1;CommandLine='wmic shadowcopy delete'}); n=(ev @{Id=1;CommandLine='wmic process get name'}) }
 @{ r='interlock_rundll32_wasd_cleanup'; p=(ev @{Id=1;Image='C:\Windows\System32\rundll32.exe';CommandLine='rundll32 C:\Windows\Temp\tmp41.wasd,x'}); n=(ev @{Id=1;Image='C:\Windows\System32\rundll32.exe';CommandLine='rundll32 shell32.dll,Control_RunDLL'}) }
 @{ r='interlock_chrome_updater_runkey'; p=(ev @{Id=13;TargetObject='HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Chrome Updater'}); n=(ev @{Id=13;TargetObject='HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive'}) }
 @{ r='play_tooling_in_public_music_exec'; p=(ev @{Id=1;Image='C:\Users\Public\Music\svc.exe'}); n=(ev @{Id=1;Image='C:\Program Files\App\app.exe'}) }
 @{ r='play_tooling_in_public_music_note'; p=(ev @{Id=11;TargetFilename='C:\Users\Public\Music\ReadMe.txt'}); n=(ev @{Id=11;TargetFilename='C:\Users\Public\Music\song.mp3'}) }
 @{ r='medusa_openrdp_fDenyTSConnections'; p=(ev @{Id=1;CommandLine='reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /d 0 /f'}); n=(ev @{Id=1;CommandLine='reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"'}) }
 @{ r='medusa_openrdp_netsh_3389'; p=(ev @{Id=1;Image='C:\Windows\System32\netsh.exe';CommandLine='netsh advfirewall firewall add rule name="rdp" dir=in protocol=tcp localport=3389 action=allow'}); n=(ev @{Id=1;Image='C:\Windows\System32\netsh.exe';CommandLine='netsh interface show interface'}) }
 @{ r='rdp_registry_enable_tamper'; p=(ev @{Id=13;TargetObject='HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections';Details='DWORD (0x00000000)'}); n=(ev @{Id=13;TargetObject='HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections';Details='DWORD (0x00000001)'}) }
 @{ r='ghost_disable_defender_setmppreference'; p=(ev @{Id=1;CommandLine='powershell Set-MpPreference -DisableRealtimeMonitoring 1 -MAPSReporting Disabled'}); n=(ev @{Id=1;CommandLine='powershell Set-MpPreference -ScanScheduleDay 2'}) }
)

$pass=0; $fail=0
foreach ($c in $cases) {
  $pred = $rules[$c.r]
  $posOk = [bool](& $pred $c.p)
  $negOk = -not [bool](& $pred $c.n)
  if ($posOk -and $negOk) { $pass++; Write-Host ("PASS  {0}" -f $c.r) -ForegroundColor Green }
  else { $fail++; Write-Host ("FAIL  {0}  (positive fired={1}, negative silent={2})" -f $c.r,$posOk,$negOk) -ForegroundColor Red }
}
Write-Host ("`nunit tests: {0}/{1} passed" -f $pass, ($pass+$fail)) -ForegroundColor Cyan
if ($fail) { exit 1 }
