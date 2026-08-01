# detections-as-code

A curated, **CI-linted** library of [Sigma](https://github.com/SigmaHQ/sigma) detections mapped to
MITRE ATT&CK. Each rule targets a **behavior an adversary can't cheaply change**, not a perishable
file hash, and carries an explicit false-positive note and a source reference.

Every rule is generated as a first draft by an [AI threat-hunting pipeline](https://github.com/spencer333/ai-threat-hunting-pipeline),
**verified by a human**, and gated by CI (`sigma check` on every push). Portfolio project 2 of 5 —
see the career roadmap.

[![sigma-lint](https://github.com/spencer333/detections-as-code/actions/workflows/sigma-lint.yml/badge.svg)](https://github.com/spencer333/detections-as-code/actions/workflows/sigma-lint.yml)

> **Enabling CI:** the `sigma-lint` workflow is included in the repo tree but must be added by an
> account whose token carries the `workflow` scope. To activate it:
> `gh auth refresh -h github.com -s workflow`, then
> `git add .github/workflows/sigma-lint.yml && git commit -m "Add CI" && git push`. The badge above
> goes live once the first run completes.

## Layout
```
rules/<attack-tactic>/<threat>_<behavior>.yml   # one behavior per file, ATT&CK-tagged
.github/workflows/sigma-lint.yml                # CI: sigma check + Splunk conversion smoke test
coverage.md                                     # ATT&CK coverage table + known gaps
coverage-navigator-layer.json                   # ATT&CK Navigator layer (import to visualize coverage)
CONTRIBUTING.md                                 # the detect-as-code process (how a rule gets in)
advisory-pipeline.md                            # continuous advisory -> detection loop (A3)
evals/                                          # detection-coverage benchmark + regression harness
tests/                                          # detection unit tests (positive/negative per rule)
```

## Are the rules any good? (the benchmark)
Rules are tested two ways, not just linted:
- **Unit-tested (logic):** every rule fires on its advisory-documented IOC and stays silent on a
  benign near-miss — **10/10 (100%)** via [`tests/run_tests.ps1`](tests/run_tests.ps1).
- **Validated (real telemetry):** the rule fired on a **real** attack sample with 0 false positives
  across a 20-sample corpus — **3/10 rules, 4/12 techniques** via [`evals/`](evals/). This is the
  honest number that only real attacker telemetry can move (see [`evals/README`](evals/README.md)).

Both matter: unit-tested proves the rule says what you meant; validated proves a real attacker trips
it. Keeping them separate is the point — a rule can pass its unit test and still miss the real world.

## Current detections
| Rule | Threat | ATT&CK | Source |
|---|---|---|---|
| `persistence/interlock_chrome_updater_runkey` | Interlock | T1547.001, T1036.005 | AA25-203A |
| `defense_evasion/interlock_rundll32_wasd_cleanup` | Interlock | T1218.011, T1070.004 | AA25-203A |
| `credential_access/akira_lsass_comsvcs_minidump` | Akira | T1003.001 | AA24-109A |
| `impact/akira_vss_shadow_delete_wmi` | Akira | T1490 | AA24-109A |
| `execution/play_tooling_in_public_music` (2 rules) | Play | T1036, T1486 | AA23-352A |
| `lateral_movement/medusa_openrdp_enable_rdp` (2 rules) | Medusa | T1021.001, T1562.004 | AA25-071A |

**8 detections across 4 ransomware families, 6 ATT&CK tactics.** See [coverage.md](coverage.md).
Import [coverage-navigator-layer.json](coverage-navigator-layer.json) into the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (*Open Existing Layer → Upload*)
to render the coverage heatmap — the cleanest single image for a résumé or LinkedIn post.

## Use
```bash
pip install sigma-cli pysigma-backend-splunk
sigma check rules/                       # validate everything
sigma convert -t splunk -f default rules/credential_access/akira_lsass_comsvcs_minidump.yml
# swap -t for elasticsearch / microsoft365defender (KQL) / etc.
```

## Why it's built this way
Detections-as-code applies software engineering to detection content: version control, code review,
CI validation, and ATT&CK-tagged coverage tracking. Rules are portable Sigma, so the same library
compiles to Splunk SPL, Elastic, or Sentinel KQL — write once, deploy to any SIEM.
