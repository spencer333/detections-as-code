# Advisory → Detection pipeline (continuous growth)

How new detections enter this library continuously, from published threat intel, with a human gate.
This is the "A3" workflow: fan out over advisories, draft with the pipeline, verify and merge by hand.

## The loop
1. **Feed.** A list of new advisories (CISA #StopRansomware, vendor reports). Manual, or on a schedule.
2. **Fan out (parallel).** Run each advisory through the AI hunting pipeline
   ([ai-threat-hunting-pipeline](https://github.com/spencer333/ai-threat-hunting-pipeline)):
   IOCs → ATT&CK → Sigma → SPL, evidence-gated. N advisories run concurrently (the async fan-out).
3. **QA verdict.** Each returns pass/partial/conflict + a run-trace. `partial` here just means the
   live-Splunk dry-run was skipped (no Splunk configured), not a logic failure.
4. **Human gate (required).** A person reads the advisory, verifies the mapping, and authors the
   shipping rule targeting a durable *behavior*, not a hash. The model drafts; the human owns what merges.
5. **PR.** Commit the rule to `rules/<tactic>/`; update `coverage.md` + `evals/detection_coverage.json`.
6. **CI.** `sigma-lint` validates on push; `evals/run_coverage.ps1` recomputes the benchmark.

## Scheduling it
Run steps 1–2 on a timer (Windows Task Scheduler / cron / the orchestrator scheduler): pull new
advisory URLs, fan out the hunts, and open a **draft** PR with the candidate rules for review. The
merge stays manual on purpose — a wrong detection shipped unattended erodes trust (see the EVTX
validation lab, where a plausible rule would have missed a real LSASS dump). Automation drafts; a
human merges.

## Demo (2026-07-31)
Ran CISA AA25-050A (Ghost / Cring ransomware) through the pipeline. Standout behavior: Ghost disables
Microsoft Defender with `Set-MpPreference -DisableRealtimeMonitoring 1 -DisableBehaviorMonitoring 1 ...`.
A human authored [`rules/defense_evasion/ghost_disable_defender_setmppreference.yml`](rules/defense_evasion/ghost_disable_defender_setmppreference.yml)
(**T1562.001**, a technique the library didn't cover). The library grew to 10 rules.

Note: the coverage benchmark's validated share **dropped** (33% → 30%) when the unvalidated rule was
added. That is correct — adding breadth without proving it lowers the validated share until you
validate the new rule against telemetry (Atomic Red Team T1562.001). The number keeps you honest
about the gap between "have a rule" and "proven it fires."
