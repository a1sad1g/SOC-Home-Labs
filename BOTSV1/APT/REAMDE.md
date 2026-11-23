# BOTS v1: APT Scenario (Po1s0n1vy)

Write-up of the **APT scenario** from Splunk Boss of the SOC v1 (questions 101-119). The scenario follows the **Po1s0n1vy** group as it targets Wayne Enterprises, defaces the company website `imreallynotbatman.com`, and stages further attacks.

> **Spoiler warning:** This document contains answers and solution queries.

---

## Scenario Summary

Po1s0n1vy scanned the Wayne Enterprises web server for vulnerabilities, identified it as a Joomla site, brute-forced the admin login, uploaded a malicious executable, and defaced the site. Open-source research on the attacker's dynamic DNS domain and infrastructure then tied the activity to the group's other known assets and malware.

### Key Entities

| Entity | Value |
|--------|-------|
| Victim website | `imreallynotbatman.com` |
| Victim web server | `192.168.250.70` |
| Scanner IP | `40.80.148.42` |
| Attacker infrastructure IP | `23.22.63.114` |
| Attacker FQDN (dynamic DNS) | `prankglassinebracket.jumpingcrab.com` |
| CMS | Joomla |
| Uploaded executable | `3791.exe` |
| Defacement file | `poisonivy-is-coming-for-you-batman.jpeg` |

## Attack Timeline (Kill Chain View)

| Phase | What happened | Questions |
|-------|---------------|-----------|
| Reconnaissance | Web vulnerability scan with Acunetix from `40.80.148.42`; site fingerprinted as Joomla | 101-103 |
| Weaponization / Infrastructure | Dynamic DNS domain and pre-staged domains tied to `23.22.63.114` | 105-107 |
| Exploitation | Brute force of the Joomla admin login from `23.22.63.114` (412 unique passwords) | 108, 114-119 |
| Initial access | Successful admin login from `40.80.148.42` using the correct password | 116, 118 |
| Installation | Executable `3791.exe` uploaded to the server | 109-110 |
| Actions on objectives | Website defaced with a custom image | 104 |
| Attribution / OSINT | Related malware and whois details pivoted from the attacker's infrastructure | 106-107, 111-113 |


