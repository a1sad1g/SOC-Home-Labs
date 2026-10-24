# SOC Home Lab Project 🛡️

A home lab built to simulate a Security Operations Center (SOC) environment, with the goal of understanding attack detection by building a full Attacker/Defender setup.

## 🎯 Project Goal
Build a lab environment to simulate, monitor, and analyze cyberattacks using SIEM tools, in order to develop practical skills for working as a SOC Analyst.

## 🏗️ Architecture

All machines run inside VMware on an isolated network (Host-Only / dedicated NAT).

| Machine | Role | Installed Tools |
|---|---|---|
| Windows Server 2016 | Victim machine | Splunk Universal Forwarder, Sysmon |
| Splunk Enterprise | SIEM - log collection & analysis | Splunk Enterprise |
| Kali Linux | Attacker machine | Penetration testing tools |

### Network Diagram
```
[Kali Linux - Attacker] 
        |
        |  (same isolated network)
        |
[Windows Server 2016 - Victim]
   - Sysmon (detailed system event logging)
   - Splunk Universal Forwarder (sends logs)
        |
        | (Forwarding on port 9997)
        v
[Splunk Enterprise - SIEM]
   - Receives logs
   - Indexing
   - Search & Correlation
```
