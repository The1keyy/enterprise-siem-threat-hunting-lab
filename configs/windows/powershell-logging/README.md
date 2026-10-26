# powershell-logging

> REQUIRES WINDOWS VALIDATION
> Run on: both
> Status: SYNTAX VALID

`enable-ps-logging.ps1` sets Script Block Logging so event 4104 is written, and Module Logging for every module. It sets Transcription to off.

Transcription is off because the transcript file stores what was typed, including passwords, and it is not an event channel the agent collects. Turn it on only for a single lab task that deletes the files afterward.

`-WhatIf` skips the registry writes and `wevtutil`. The PowerShell Operational log maximum is set to 256 MB.
