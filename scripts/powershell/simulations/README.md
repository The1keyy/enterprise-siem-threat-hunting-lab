# scripts/powershell/simulations/

> **LAB ONLY. REQUIRES WINDOWS VALIDATION.** Snapshot every VM before running anything here.

These are safe attack simulations that generate telemetry for SentinelForge detections. Every
simulation:
- Refuses to run unless the machine is joined to `sentinelforge.lab`.
- Requires the `-IUnderstandLabOnly` switch.
- Has a matching `*-Cleanup.ps1`.
- References an Atomic Red Team test ID where one applies.

**Status:** `NOT TESTED`. No script here has run on a lab VM.
