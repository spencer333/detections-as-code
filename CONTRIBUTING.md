# How a detection gets into this library (the detect-as-code process)

This mirrors Station 4 (the T1 gate) of the defensive workflow.
Nothing merges that hasn't cleared every step.

1. **Source.** Start from a citable source — a CISA/vendor advisory, an incident, or a lab
   detonation (Atomic Red Team). Record the reference URL in the rule's `references:`.
2. **Draft.** Run the source through the [AI hunting pipeline](https://github.com/spencer333/ai-threat-hunting-pipeline)
   (`run_threat_hunt`) to get IOCs → ATT&CK IDs → a first-draft Sigma rule, evidence-gated.
3. **Verify (human, required).** Re-read the source. Confirm the ATT&CK mapping, and choose a
   **behavioral** selector over a hash wherever possible (hashes rotate; behaviors don't). Rewrite
   the draft as needed — the pipeline drafts, you own what ships.
4. **False-positive pass.** Every rule MUST have a `falsepositives:` note. If you can't name the
   benign activity that would trip it, you don't understand the rule well enough to ship it.
5. **Tag.** Add `attack.<tactic>` and `attack.t<technique>` tags. File under `rules/<tactic>/`.
6. **Lint.** `sigma check rules/` locally, then let CI (`sigma-lint.yml`) confirm on push. A rule
   that fails `sigma check` does not merge.
7. **Cover.** Update [coverage.md](coverage.md) so the ATT&CK coverage number moves.

## Rule conventions
- One behavior per rule; `status: experimental` until validated against real telemetry, then `test`/`stable`.
- Prefer `process_creation` / `registry_set` / `file_event` logsources (Sysmon-backed).
- `level:` reflects fidelity: `high` = near-zero benign use; `medium` = needs correlation.
- Author line notes the pipeline + `T1-verified` so provenance is honest.
