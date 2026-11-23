# Splunk Boss of the SOC (BOTS) v1: Investigation Write-Up

A walkthrough of my investigation of the **Splunk Boss of the SOC version 1** dataset, covering the methodology, the SPL used, and the findings for each question.

> **Spoiler warning:** This repository contains answers and solution queries for BOTS v1. If you want to attempt the challenge yourself, do that first.

---

## About BOTS v1

Boss of the SOC is a blue-team Capture-the-Flag exercise created by Splunk. Version 1 presents a realistic, pre-indexed dataset from a fictional company, **Wayne Enterprises**, and asks analysts to investigate it using Splunk. The questions are grouped into two scenarios:

| Scenario | Theme | Focus |
|----------|-------|-------|
| **APT** | Web server compromise and defacement | Reconnaissance, exploitation, attacker infrastructure, attribution |
| **Ransomware** | Ransomware infection inside the network | Initial delivery, endpoint activity, file encryption, lateral impact |

The dataset is a mix of network, web, endpoint, and security-appliance telemetry, which makes it a good exercise in correlating multiple sources into a single attack timeline.

## Objectives

- Practice SPL searching, filtering, statistics, and field extraction
- Reconstruct attacker activity across the kill chain
- Correlate network, web, and host data sources
- Document the investigation in a clear, repeatable way

## Environment

| Item | Details |
|------|---------|
| Splunk | Splunk Enterprise |
| Host OS | Windows10 |
| Dataset | `botsv1_data_set` |
| Index | `botsv1` |
| Time range | All time (`earliest=0`), since the data is from 2016 |

### Setup

1. Install Splunk Enterprise (a free trial license is sufficient).
2. Download the BOTS v1 dataset from the official Splunk BOTS GitHub repository.
3. Extract the dataset app into `$SPLUNK_HOME/etc/apps/`.
4. Restart Splunk.
5. Confirm the data loaded:

```spl
index=botsv1 earliest=0
| stats count by sourcetype
| sort - count
```


## Tools and References

- [Splunk Enterprise](https://www.splunk.com/)
- Splunk Search Processing Language (SPL) documentation
- VirusTotal, for hash and domain reputation lookups
- Whoxy for IP addresses

## Disclaimer

This write-up is for educational purposes. All data comes from a publicly released, fictional training dataset. Boss of the SOC is a Splunk project, and this repository is not affiliated with or endorsed by Splunk.
