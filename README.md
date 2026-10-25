# SOC Home Lab Project 🛡️

A home lab built to simulate a Security Operations Center (SOC) environment, with the goal of understanding attack detection by building a full Attacker/Defender setup.

## 🎯 Project Goal
Build a lab environment to simulate, monitor, and analyze cyberattacks using SIEM tools, in order to develop practical skills for working as a SOC Analyst.

## 🏗️ Architecture

All machines run inside VMware on an isolated network (Host-Only) only splunk enterprise it's not on VM.

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


## ✅ Progress So Far

1. Set up the VMware environment and created the three virtual machines.
2. Installed and configured **Splunk Enterprise** as the central log collection server.
3. Installed **Sysmon** on Windows Server 2016 with a Sysmon configuration file to capture detailed events (Process Creation, Network Connections, Registry Changes, etc.).
4. Installed and connected **Splunk Universal Forwarder** on the Windows Server to forward logs to Splunk Enterprise.
5. Verified logs (Sysmon logs + Windows Event Logs) are being received correctly on the Splunk dashboard.
6. Prepared **Kali Linux** as the attack platform on the same network.

## 🔜 Next Steps
- Execute simulated attack scenarios from Kali against the Windows Server.
- Write SPL (Search Processing Language) queries in Splunk to detect those attacks.
- Build Dashboards and Alerts for each scenario.
- Document each attack with: description - tool used - detection method - IOCs.

## 📚 References
- [Sysmon - Microsoft Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Documentation](https://docs.splunk.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---
*This project is for educational purposes only, in an isolated lab environment.*
