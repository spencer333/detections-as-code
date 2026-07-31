# Rules

Sigma detections organized by MITRE ATT&CK tactic. Every rule is validated by CI
([`sigma-lint`](../.github/workflows/sigma-lint.yml)) on each push and carries a false-positive
note plus a source reference. See [../coverage.md](../coverage.md) for the ATT&CK coverage table and
[../CONTRIBUTING.md](../CONTRIBUTING.md) for how a rule gets in.

| Tactic folder | Rules |
|---|---|
| `credential_access/` | Akira — LSASS dump via comsvcs.dll MiniDump (T1003.001) |
| `defense_evasion/` | Interlock — rundll32 executing `.wasd` cleanup DLL (T1218.011, T1070.004) |
| `execution/` | Play — tooling / ransom note in `C:\Users\Public\Music` (T1036, T1486) |
| `impact/` | Akira — Volume Shadow Copy deletion via WMI (T1490) |
| `lateral_movement/` | Medusa — RDP enabled via `fDenyTSConnections` + netsh 3389 (T1021.001, T1562.004) |
| `persistence/` | Interlock — "Chrome Updater" Run-key (T1547.001, T1036.005) |

Validate locally: `sigma check rules/`
