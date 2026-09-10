# Scanning an endpoint without a domain admin

An endpoint scan does not need an administrator. Nothing on the scan path tests
for one: the scripts read, and the only thing they write is a base64 staging
file under the connecting account's own `%TEMP%`.

Two Windows defaults are what make a privileged account the path of least
resistance, and both are grantable without one:

1. **Only local Administrators may open a WinRM session.** Until an account is
   in **Remote Management Users** on the target, every WS-Man call is refused,
   whatever the file permissions say. The account also needs the *Access this
   computer from the network* user right (`SeNetworkLogonRight`), which
   `Users` holds by default but hardening baselines often strip.
2. **One account cannot read another account's profile.** `C:\Users\<someone>`
   grants that user, `SYSTEM` and `Administrators` and nobody else, so a
   non-admin account reads its own profile and no more.

So whether a least-privilege account is sufficient depends entirely on **what
you point it at**. Use **Check access** on the last step of the endpoint wizard
to find out before running a scan; it reports which profiles the credential can
actually enumerate and whether it can stage a file.

---

## The grants

Run these on each target, or push them by Group Policy. `svc_dspm_scan` is a
plain domain user with no other rights.

### 1. Let the account connect

```powershell
Add-LocalGroupMember -Group "Remote Management Users" -Member "CONTOSO\svc_dspm_scan"
```

That alone is enough to open the session. It does **not** make the account an
administrator, and it does not grant it any file access.

`Set-PSSessionConfiguration` is **not** the lever here, and granting rights on
`Microsoft.PowerShell` will not let this account in. The scanner opens the WinRS
`cmd` shell resource, so access is governed by the WinRM service `RootSDDL` —
which `Enable-PSRemoting` populates with `BUILTIN\Administrators` and
`BUILTIN\Remote Management Users`.

For the same reason, a hardening baseline that sets **Allow Remote Shell
Access** to Disabled breaks scanning even though PowerShell remoting still
works. If scans fail immediately after a GPO change, check that setting first:

```powershell
Get-Item WSMan:\localhost\Shell\AllowRemoteShellAccess
```

By GPO: *Computer Configuration → Preferences → Control Panel Settings → Local
Users and Groups → Update `Remote Management Users`*, adding the account.

### 2. Let it read what you want scanned

Only what you intend to scan, and nothing else:

```powershell
$acl = Get-Acl "D:\Shared\Finance"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "CONTOSO\svc_dspm_scan", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "D:\Shared\Finance" $acl
```

To scan **every user profile** on a machine, the account needs read on
`C:\Users`. That is a genuinely broad grant — it is read access to everyone's
documents — so treat it as a deliberate decision, scope it to the machines that
need it, and prefer per-folder grants where you can.

### 3. Nothing else

The scan does not need `SeBackupPrivilege`, and adding the account to **Backup
Operators** will not help: PowerShell's `Get-ChildItem` and `Get-Content` do not
open files with backup semantics, so the privilege is never exercised. It would
grant the account the ability to read the whole disk through other tools while
doing nothing for the scan — a strictly worse trade.

---

## What still needs an administrator

**Enabling WinRM on a target that has never been prepared.** That is
`Enable-PSRemoting`, `Set-Service WinRM`, and a write to
`HKLM:\SOFTWARE\Microsoft\Ole` — service and machine state, which is
administrator work by definition.

It is **once per machine**, and it does not have to be done by this product.
Prefer Group Policy, which needs no admin credential in the console at all:

*Computer Configuration → Policies → Administrative Templates → Windows
Components → Windows Remote Management (WinRM) → WinRM Service →*
**Allow remote server management through WinRM** → Enabled.

Then set the WinRM service to start automatically and open TCP 5985 (or 5986)
from the scanner host only.

If you do use the console's **Prepare & Test target WinRM**, that step — and
only that step — wants an account in the target's local Administrators group.
It is a separate act from scanning, and the credential does not have to be the
one you scan with.

---

## The channel

WinRM traffic from this product is always encrypted.

Over HTTP (5985) the payload is wrapped in NTLM or Kerberos message encryption,
and the collector now *requires* it: `message_encryption="always"`, so a
transport that cannot encrypt raises rather than falling back to plaintext.
pywinrm's own default is `"auto"`, which sends unencrypted over HTTP whenever
the auth object does not expose a session key, without reporting it — for a
product whose payload is the customer's file content, that silent downgrade is
not an acceptable default.

Over HTTPS (5986) the channel is TLS and encryption is left to it rather than
paying for a second wrapping. Set `DSPM_WINRM_ACTIVATION_HTTPS=1` to have
activation provision an HTTPS listener.

`DSPM_WINRM_SSL_SKIP_CA_CHECK=1` disables certificate validation for the
self-signed certificate an HTTPS activation creates. It still encrypts, but it
drops MITM protection — prefer a trusted or pinned certificate in production.

---

## A note on the file-server collector

This page is about endpoint (WinRM) scans. The SMB file-server collector has a
separate, unrelated limitation: it is built on pysmb, which speaks only SMB 2.0
and 2.1 and has no SMB 3.x transport encryption. A share configured with
`Set-SmbShare -EncryptData $true` — common on domain controllers and hardened
file servers — accepts the negotiate and the NTLM auth and then resets the first
data operation (`WinError 10054`).

That is a library ceiling, not a permissions problem, and the fix is a migration
to `smbprotocol`. It needs live validation against a real encrypted share and is
tracked separately; it does not affect endpoint scans, which never touch SMB.
