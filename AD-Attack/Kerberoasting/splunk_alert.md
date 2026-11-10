# Splunk Alert: Kerberoasting Detected - RC4 TGS Request

## 1. Overview

| Item | Value |
|---|---|
| Alert name | Kerberoasting Detected - RC4 TGS Request |
| Description | RC4 encrypted Kerberos service ticket requested - possible Kerberoasting (T1558.003) |
| MITRE ATT&CK technique | T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting |
| MITRE ATT&CK tactic | Credential Access |
| Data source | Windows Security Event Log, Event ID 4769 |
| Severity | High |

## 2. Detection Logic

In a Kerberoasting attack, an attacker with any valid domain account requests Kerberos service tickets (TGS) for service accounts that have a Service Principal Name (SPN). Part of each ticket is encrypted with the service account's password hash, so the attacker can crack it offline to recover the password.

Offensive tools such as Rubeus and Impacket's GetUserSPNs typically request tickets encrypted with **RC4-HMAC (0x17)**, because RC4 is much faster to crack than AES. Modern domains negotiate AES (0x11 / 0x12) by default, so a successful RC4 service ticket request for a user service account is a strong indicator of Kerberoasting.

## 3. Prerequisites

- **Audit Kerberos Service Ticket Operations** must be enabled (Success) on the domain controllers.
  Path: `Advanced Audit Policy Configuration > Account Logon > Audit Kerberos Service Ticket Operations`
- Domain controller Security logs must be forwarded to Splunk (for example with the Universal Forwarder) into `index=windows` with `sourcetype="WinEventLog:Security"`.
- The Splunk Add-on for Microsoft Windows is recommended so that field names such as `Ticket_Encryption_Type`, `Service_Name`, `Account_Name`, and `Client_Address` are extracted.

## 4. Detection Query (SPL)

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17 NOT Service_Name="krbtgt" NOT Service_Name="*$"
| bin _time span=5m
| stats count as requests values(Service_Name) as targeted_services by _time Client_Address Account_Name
| table _time Account_Name Client_Address targeted_services requests
| sort - requests
```

### Query Breakdown

| Part | Purpose |
|---|---|
| `index=windows sourcetype="WinEventLog:Security"` | Windows Security events |
| `EventCode=4769` | A Kerberos service ticket was requested |
| `Ticket_Encryption_Type=0x17` | RC4-HMAC encryption, the main indicator |
| `NOT Service_Name="krbtgt"` | Exclude TGT-related requests |
| `NOT Service_Name="*$"` | Exclude computer accounts (names ending in `$`) and focus on user service accounts |
| `bin _time span=5m` | Group events into 5-minute buckets |
| `stats count ... by _time Client_Address Account_Name` | Count requests and collect targeted services per user and source address |
| `table ...` | Show only the fields an analyst needs |
| `sort - requests` | Highest request count first |

### Key Output Fields

- **Account_Name**: the account that requested the tickets (the likely compromised account).
- **Client_Address**: the source host of the requests.
- **targeted_services**: the service accounts (SPNs) that were targeted.
- **requests**: number of RC4 ticket requests in the 5-minute window. A high value suggests bulk SPN enumeration.

## 5. Alert Configuration

### Settings

| Setting | Value |
|---|---|
| Title | Kerberoasting Detected - RC4 TGS Request |
| Description | RC4 encrypted Kerberos service ticket requested - possible Kerberoasting (T1558.003) |
| Search | The query in section 4 |
| App | Search & Reporting (search) |
| Permissions | Private |
| Alert type | Scheduled |

### Schedule

| Setting | Value |
|---|---|
| Schedule | Run on Cron Schedule |
| Time Range | Last 5 minutes |
| Cron Expression | `*/5 * * * *` (every 5 minutes) |
| Expires | 24 hour(s) |

The time range and cron interval both match `span=5m`, so each run covers one new window and the same events are not re-evaluated in overlapping runs.

### Trigger Conditions

| Setting | Value |
|---|---|
| Trigger alert when | Number of Results |
| Condition | is greater than 0 |
| Trigger | Once |
| Throttle | Enabled |
| Suppress triggering for | 5 minute(s) |

### Trigger Actions

| Action | Setting |
|---|---|
| Add to Triggered Alerts | Severity: High |

## 6. Screenshot



## 7. Validation

- The alert appears in **Searches, Reports, and Alerts** with status `Enabled`.
- The **Next Scheduled Time** column shows the next run.
- After the attack is simulated, the alert appears under **Activity > Triggered Alerts**.
- Running the search manually over the attack time range returns the attacker's account, source IP, and targeted services.

## 10. Related Files

- Attack: `kerberoasting_attack.md`
- Investigation: `kerberoasting_investigation.md`
