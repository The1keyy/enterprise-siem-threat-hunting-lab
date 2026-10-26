# auditd

> Run on: UBU01
> Status: NOT TESTED. auditctl is not on this Mac, so the rules file is not SYNTAX VALID.

## What it does

`sentinelforge.rules` watches four things:

- `execve` for login uids at or above 1000, skipping unset auid
- writes to sudoers
- writes to passwd, group, shadow, and gshadow
- writes to `sshd_config` and `sshd_config.d`

Reads are not watched. There is no rule for all file opens or all network connects.

## Where it goes

`/etc/audit/rules.d/sentinelforge.rules`. **VERIFY** that directory on Ubuntu 24.04.

## How to apply

12C copies it and loads it. From the notes, the commands to confirm on UBU01 are:

```bash
augenrules --check
augenrules --load
auditctl -l | grep sentinelforge_
```

`auditctl -R` is the older one-shot load. A comment line or a missing directory can make it fail. **VERIFY** both on UBU01. Do not run `auditctl -e 2`.

The b32 `execve` line needs the 32-bit syscall table. **VERIFY** it loads on the amd64 kernel. If it does not, delete that one line and load again.

## How to verify

`ausearch -k sentinelforge_execve -ts recent` after a normal command such as `id`. Not done.
