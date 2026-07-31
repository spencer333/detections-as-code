---
type: linkedin-draft
project: 02-detections-as-code
status: draft (T1-authored; regenerate variants via linkedin_post_generator when GPU free)
---

# LinkedIn post — Project 2 launch

Detections-as-code, explained with 8 real rules.

I turned four 2025 CISA ransomware advisories — Interlock, Akira, Play, and Medusa — into 8 tested
Sigma detections, version-controlled and CI-linted on every push.

The rule I keep pointing people to is the Play one. CISA says it outright: Play recompiles its binary
for every attack, so every deployment has a unique hash. There is nothing static to block. So the
detection ignores hashes entirely and watches for what Play actually does — stage its tools and drop
its ransom note in C:\Users\Public\Music\, a folder where executables never belong.

That's the whole philosophy of the repo: detect behaviors an adversary can't cheaply change, not
file hashes they rotate between victims.

What's in it:
🔹 8 rules across 6 ATT&CK tactics (LSASS dumping, shadow-copy deletion, RDP-enable, run-key persistence…)
🔹 A GitHub Action that runs `sigma check` + a Splunk-conversion smoke test on every push — a broken
   rule fails the build and never merges
🔹 Every rule has a false-positive note and a source reference. If I can't name what would trip it, it
   doesn't ship.
🔹 Portable Sigma → compiles to Splunk, Elastic, or Sentinel KQL. Write once, deploy anywhere.

Each rule started as a draft from an AI pipeline and was verified by hand before merging — automation
for speed, a human for what ships.

Repo + writeups in the comments 👇

#DetectionEngineering #DetectionAsCode #Sigma #MITREATTACK #BlueTeam #SOC #ThreatDetection #Cybersecurity

---

## Notes for posting
- Best image: the ATT&CK Navigator coverage layer (generate from coverage.md) or the green CI check.
- First comment: GitHub repo link.
- Tie-in: this is the library that Project 1's pipeline feeds and Project 3's home-SOC lab tests against.
