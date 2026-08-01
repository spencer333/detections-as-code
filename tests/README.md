# tests — detection unit tests

Fast logic tests for every rule: a **positive** event (the exact IOC the advisory documents) that the
rule MUST fire on, and a **negative** benign near-miss it must stay silent on. Run in seconds, no
telemetry needed.

```powershell
powershell -File .\run_tests.ps1
# -> PASS/FAIL per rule; exits non-zero on any failure
```

## Two kinds of "tested" (don't conflate them)
This repo tracks coverage two ways, on purpose:

| Metric | Means | Current |
|---|---|---|
| **unit-tested** (`tests/`) | rule logic is correct: fires on the documented IOC, silent on a benign near-miss | **10/10 (100%)** |
| **validated** (`evals/`) | rule fired on a **real** attack sample with no false positive | **3/10 (30%)** |

Unit-tested proves the rule *says* what you meant. Validated proves a *real attacker* trips it. A rule
can pass its unit test and still be wrong about the real world (see the EVTX lab: the comsvcs rule
passed review but missed a real by-PID dump). So both numbers are kept, and only real telemetry moves
`validated`.

## Moving `validated`
The 7 unvalidated rules need real telemetry for their technique. Generate it with Atomic Red Team on a
lab VM — see the A5 purple-team playbook in the home-soc-lab project. That is the one step that raises
`validated`, and it needs a disposable VM (attack execution is not safe on a production host).
