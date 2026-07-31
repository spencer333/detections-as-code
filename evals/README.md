# evals — detection-coverage benchmark + regression harness

The **objective function** for this library. Anyone can add rules; the question that matters is
"how many of them actually fire on real attacks, and do any of them fire on benign activity?" This
turns that into a number you can move.

## Current benchmark (2026-07-31)
Run `run_coverage.ps1`:
```
False positives: 0 across 20 samples
Rules validated: 3 / 9 (33%)
Techniques with a validated rule: 4 / 11 (36%)
```
`validated` = the rule fired on a real attack sample of its technique, with **zero false positives**
across a 20-sample regression corpus (public [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)).

## Regression result (what the harness proved)
Every rule that fired, fired on the right sample. Every rule stayed silent on unrelated attacks:
- `akira_lsass_comsvcs_minidump` fired on the comsvcs sample and was **silent on 6 other LSASS-dump
  methods** (mimikatz, MiniDumpWriteDump, rdrleakdiag, hashdump, reflection, memssp). Precise, not broad.
- `rdp_registry_enable_tamper` fired only on real RDP registry tampering, silent on 4 RDP-tunnel / SharpRDP samples.
- The narrow-by-design rules (`rundll32_wasd`, `chrome_updater`) stayed silent on all generic samples.
- **0 false positives across the corpus.**

## Files
| File | What |
|---|---|
| `detection_coverage.json` | the benchmark data: each rule -> techniques, level, validated?, evidence |
| `run_coverage.ps1` | computes the coverage numbers from the JSON |
| `regression.ps1` | runs every rule against a directory of `.evtx` samples; prints the fire matrix |

## Run it yourself
```powershell
# 1) fetch a corpus (samples not committed - binary attack telemetry):
#    gh api -H "Accept: application/vnd.github.raw" \
#      "repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/<path>" > samples/<name>.evtx
# 2) regression matrix (native Get-WinEvent; no attack runs on your host):
powershell -File .\regression.ps1 -EvtxDir .\samples
# 3) the benchmark number:
powershell -File .\run_coverage.ps1
```

## Backlog — how to move the number
6 rules are precise but unproven (no matching sample yet). To validate them, generate telemetry with
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) and re-run:
- `akira_vss_shadow_delete_wmi` (T1490) — Atomic T1490 (vssadmin/wmic shadow delete)
- `interlock_chrome_updater_runkey` (T1547.001) — custom atomic writing a "Chrome Updater" Run value
- `interlock_rundll32_wasd_cleanup` (T1218.011) — custom atomic: `rundll32 tmp41.wasd,x`
- `play_tooling_in_public_music_*` (T1036 / T1486) — stage a file in `C:\Users\Public\Music`
- `medusa_openrdp_fDenyTSConnections` (T1021.001) — `reg add ... fDenyTSConnections /d 0`

Each validated rule raises the number. That is the loop.
