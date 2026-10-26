# agent-windows

> REQUIRES WINDOWS VALIDATION
> Run on: both (DC01 and WS01)
> Status: SYNTAX VALID after the Mac XML parse. Not installed.

## What it does

`ossec.conf.snippet` is the block to merge into `C:\Program Files (x86)\ossec-agent\ossec.conf`. It points the agent at `<WAZUH_MANAGER_IP>` and collects every channel in `configs/windows/channels.md`.

## Where it goes

On DC01 and WS01, inside the existing `<ossec_config>`. The stock 4.14.9 agent file already has Security and System. Delete those two stock blocks while merging. The stock Security query excludes event 5145, and SF-011 needs 5145. Leave the stock Application block. It is not in the channel list.

## How to apply

Replace `<WAZUH_MANAGER_IP>` with `10.10.10.40`. Restart the Wazuh service. Step 12C's install script does this merge. This folder does not.

## How to verify

On the Mac, `pytest tests/configs/test_agent_snippets.py`. On the host, after a snapshot, start a process and confirm a Sysmon event arrived on WAZUH01. That has not been done.

## Matrix check

Security is an allow-list: 4624, 4625, 4688, 4720, 4728, 4732, 4756, 5140, 5145. 4688 is the command-line event from Step 12A, not an SF alert. 5156 and the other stock exclusions stay out.

PowerShell Operational keeps 4104 only. Module Logging 4103 is not in the matrix.

System, Sysmon Operational, and WinRM Operational have no query. System and WinRM have no event ID to allow. Sysmon's pinned config logs more than events 1 and 3, and a query would drop those.
