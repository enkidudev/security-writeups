---
title: "HTB Trick: DNS Enumeration, LFI, SMTP Mailbox Poisoning, and Fail2Ban"
description: "An evidence-led walkthrough of Trick, from DNS and virtual-host enumeration to PHP execution and a Fail2Ban privilege-escalation path."
date: 2026-11-08
category: "Linux / Web Security"
difficulty: "Easy"
tags:
  - Hack The Box
  - Linux
  - DNS
  - LFI
  - SMTP
  - PHP
  - Fail2Ban
published: true
slug: "htb-trick"
---

# Overview

**Machine:** Trick  
**Platform:** Hack The Box  
**Target hostname:** `trick.htb`  
**Operating system:** Linux  
**Result:** User compromise directly observed. Root-flag retrieval was operator-confirmed.

Trick demonstrates how multiple services can combine into a compromise path. DNS zone transfer exposed an application hostname, virtual-host enumeration uncovered a second web application, and a local file inclusion (LFI) issue became PHP code execution when combined with SMTP delivery to a local mailbox. Local enumeration then identified a Fail2Ban configuration weakness.

```text
DNS AXFR
  -> virtual-host discovery
  -> marketing application LFI
  -> SMTP delivery to /var/mail/michael
  -> PHP execution as michael
  -> writable Fail2Ban action directory
  -> privileged service restart and SSH ban event
  -> root-flag access
```

## 1. Reconnaissance and DNS enumeration

The initial scan identified SSH, SMTP, DNS, and HTTP services.

| Port | Service | Relevance |
|---:|---|---|
| 22/tcp | SSH | Later used to trigger a Fail2Ban event |
| 25/tcp | SMTP | Accepted local mail delivery |
| 53/tcp | DNS | Exposed a zone transfer |
| 80/tcp | HTTP | Hosted multiple name-based applications |

A DNS zone transfer disclosed `preprod-payroll.trick.htb`:

```bash
dig @"$TARGET" trick.htb AXFR
```

The transfer exposed one useful hostname, but it did not reveal the entire web attack surface. The payroll application was investigated separately, including a SQL injection issue. That branch was not the route used for initial access.

## 2. Virtual-host discovery

The marketing application was found by fuzzing the HTTP `Host` header using the observed `preprod-` naming convention:

```bash
ffuf \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "http://$TARGET/" \
  -H 'Host: preprod-FUZZ.trick.htb' \
  -ac -ic -t 100
```

The `marketing` result returned HTTP 200 and exposed `preprod-marketing.trick.htb`.

This was an important enumeration step: the DNS transfer revealed one hostname, while targeted virtual-host fuzzing identified another.

## 3. LFI in the marketing application

The marketing application accepted a `page` parameter. A traversal-filter bypass allowed local file inclusion:

```text
/index.php?page=....//....//...//etc/passwd
```

The response disclosed the local account:

```text
michael:x:1001:1001::/home/michael:/bin/bash
```

At this stage, the issue provided local file disclosure. Code execution required an additional source of attacker-controlled file content.

## 4. SMTP mailbox poisoning to PHP execution

The SMTP service accepted mail addressed to Michael's local mailbox:

```text
/var/mail/michael
```

The LFI parameter could include that file. Combining the two behaviors allowed attacker-controlled mail content to reach a PHP include context.

A benign marker was used first to validate PHP interpretation. A subsequent command-execution check returned:

```text
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

An interactive shell was then obtained as `michael`, and the user flag was retrieved from `/home/michael/user.txt`.

**Technical distinction:** SMTP delivery alone did not provide code execution, and LFI alone did not provide a shell. The compromise resulted from combining a writable local mail source with an application include sink.

## 5. Fail2Ban privilege escalation

Local enumeration identified the following sudo permission:

```text
(root) NOPASSWD: /etc/init.d/fail2ban restart
```

The `michael` account was also a member of the `security` group. The relevant permissions were:

```text
drwxrwx--- root security /etc/fail2ban/action.d
-rw-r--r-- root root     iptables-multiport.conf
```

The action file itself was root-owned and not directly writable by `michael`. However, the parent directory was group-writable. This distinction allowed replacement of a directory entry even though the original file did not grant write permission.

Fail2Ban used the `iptables-multiport` action. The escalation path involved replacing its `actionban` definition, restarting the service through the permitted sudo command, and generating an SSH ban event so the modified action would execute.

The first attempt to change `/bin/bash` permissions did not establish SUID execution. The effective path depended on triggering the correct Fail2Ban lifecycle event: a service restart alone did not execute `actionban`.

**Outcome qualification:** Root-flag retrieval was confirmed by the operator after the `actionban` and SSH-ban sequence. The surviving engagement record does not contain the literal root flag output or an interactive UID 0 shell transcript, so neither is claimed here.

## 6. Key lessons

- Treat DNS AXFR as a lead, not a complete inventory of virtual hosts.
- Follow DNS enumeration with targeted `Host`-header fuzzing.
- Investigate whether an LFI sink can include files populated by another reachable service.
- Validate code execution with a benign marker and an identity check before moving to post-exploitation.
- Assess directory permissions independently from the permissions of files inside the directory.
- A privileged service restart and a privileged action event are different conditions. Identify and trigger the exact event that executes the configured command.
- Keep confirmed observations separate from reproduction examples and operator-reported outcomes.

## 7. Remediation

- Restrict DNS zone transfers to authorized secondary DNS servers.
- Use parameterized SQL queries and enforce authentication server-side.
- Replace arbitrary file inclusion with a strict allowlist of application templates. Canonicalize and confine filesystem paths.
- Do not allow untrusted mail content to be interpreted as PHP or another executable format.
- Restrict `/etc/fail2ban/action.d/` and its contents to trusted administrators. Review group membership and filesystem ACLs.
- Remove unnecessary passwordless service-restart permissions and protect all configuration consumed by privileged services.

---

*This article documents a retired Hack The Box training machine. The writeup distinguishes directly observed evidence from reproduction guidance and operator-confirmed outcomes.*
