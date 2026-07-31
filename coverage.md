# ATT&CK Coverage

Detections in this library mapped to MITRE ATT&CK. This is the input to the
detection-coverage benchmark
— the number every engagement should move.

| Tactic | Technique | ID | Rule | Threat |
|---|---|---|---|---|
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | interlock_chrome_updater_runkey | Interlock |
| Defense Evasion | Masquerading | T1036.005 | interlock_chrome_updater_runkey | Interlock |
| Defense Evasion | Rundll32 | T1218.011 | interlock_rundll32_wasd_cleanup | Interlock |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | interlock_rundll32_wasd_cleanup | Interlock |
| Credential Access | LSASS Memory | T1003.001 | akira_lsass_comsvcs_minidump | Akira |
| Impact | Inhibit System Recovery | T1490 | akira_vss_shadow_delete_wmi | Akira |
| Execution / DE | Masquerading (staging path) | T1036 | play_tooling_in_public_music | Play |
| Impact | Data Encrypted for Impact (note drop) | T1486 | play_tooling_in_public_music | Play |
| Lateral Movement | Remote Desktop Protocol | T1021.001 | medusa_openrdp_enable_rdp | Medusa |
| Defense Evasion | Disable/Modify System Firewall | T1562.004 | medusa_openrdp_enable_rdp | Medusa |

**Coverage: 8 rules · 4 threats · 10 (technique × rule) mappings · 6 ATT&CK tactics.**

## Known gaps (next hunts — from the same advisories)
- **T1204.004** ClickFix malicious copy/paste (Interlock) — needs RunMRU / clipboard-to-PowerShell telemetry.
- **T1567.002** exfil to cloud (Akira RClone→Mega, Medusa RClone) — network/proxy detection, not endpoint.
- **T1027.013** encoded PowerShell (Medusa `-enc`) — high-value but FP-prone; needs tuning + amsi context.
- **T1003.003** NTDS.dit extraction (Akira) — VM-disk copy path; hard without EDR file-access telemetry.

> Regenerate this as an ATT&CK Navigator layer (JSON) once the library grows — it makes the strongest
> single portfolio image for a LinkedIn post or resume.
