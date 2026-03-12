# Azure Honeypot — Live Brute Force Detection & Response

> I Deployed a deliberately exposed Azure VM as a honeypot. Within **minutes**, automated attackers were hammering it. This documents how I detected, responded to, and hardened against a live brute force attack using Microsoft Sentinel.

---

## Environment

| | |
|---|---|
| **Platform** | Microsoft Azure + Microsoft Sentinel |
| **VM** | `soclab` |
| **Attack Type** | Brute Force / Credential Stuffing |
| **Protocol Targeted** | NTLM (RDP/SMB) |
| **Outcome** | Contained — Zero Compromise |

---

## Honeypot Setup

- Spun up an Azure VM with a **public IP and RDP exposed**
- Created a **honeypot account** with a common username to attract scanners
- Connected VM to **Microsoft Sentinel** via Log Analytics Workspace
- Waited — bots found it in minutes

---

## Attack Detected

### KQL Queries — Microsoft Sentinel

```kql
SecurityEvent
| where Computer == "soclab"
| project TimeGenerated, Account, IpAddress,
          AccountType, AuthenticationPackageName
```

### Live Attack Data

> **[<img width="1405" height="559" alt="image" src="https://github.com/user-attachments/assets/e543fa00-860e-46d9-96da-3e7d7258430c" />
]**

---

Key indicators from the results:

- **1,000+ failed logon events** in under 24 hours
- **Millisecond-apart timestamps** — fully automated botnet
- **Two attacker IP ranges:** `185.156.73.x` · `92.63.197.x` (confirmed malicious via AbuseIPDB)
- **Common username wordlist** in use: `administrator`, `ws7`, `mkt`, `paulh`, `edu`
- **All NTLM** — targeting Windows auth surface

---

## Incident Response

### 1 — Isolate

I Immediately **blocked all inbound traffic via NSG** — network isolation while investigating. No lateral movement possible.

### 2 — Hunt for Successful Logins

```kql
SecurityEvent
| where Computer == "soclab"
| where EventID == 4624           // Successful logon
| where IpAddress has_any ("185.156.73", "92.63.197")
| project TimeGenerated, Account, IpAddress, LogonType

> **[<img width="1405" height="559" alt="image" src="<img width="975" height="406" alt="image" src="https://github.com/user-attachments/assets/73f5e015-c969-45f8-a5ba-c3090dcaa19c" />
" />
]**
```

```kql
SecurityEvent
| where Computer == "soclab"
| where EventID == 4624
| summarize Count = count() by Account, IpAddress
| order by Count desc

> **[<img width="1405" height="559" alt="image" src="<img width="1786" height="814" alt="image" src="https://github.com/user-attachments/assets/fd30c7d6-e257-4c20-98c7-41a1e75e0245" />
" />
]**
```

> **No successful logons from attacker IPs. No compromise.**

---

## Hardening

### NSG Rules Applied

| Priority | Rule | Port | Source | Action |
|---|---|---|---|---|
| 300 | RDP | 3389 | `[My IP]/32` | Allow |
| 311 | Deny_Public_IP_Access | 3389 | Any | Deny |
| 65500 | DenyAllInBound | Any | Any | Deny |

> **[SCREENSHOT — NSG rules before hardening]**

> **[<img width="2850" height="680" alt="image" src="https://github.com/user-attachments/assets/699d9f22-12ce-4ea5-9ea0-7266152b8c58" />
]**

---

## Remediation & Recommendations

| Priority | Action |
|---|---|
| Immediate | Restrict RDP to trusted IP only — never expose 3389 publicly |
| Immediate | Enable account lockout — 5 failed attempts, 30-min lockout |
| Short-term | Replace public RDP with **Azure Bastion** or **JIT VM Access** |
| Short-term | Enforce MFA on all accounts via Entra ID |
| Ongoing | Connect all VMs to Sentinel — custom KQL alerts for brute force patterns |
| Ongoing | Integrate threat intel feeds (AbuseIPDB, Microsoft TI) for auto IP blocking |

> **[<img width="2850" height="680" alt="image" src="[https://github.com/user-attachments/assets/699d9f22-12ce-4ea5-9ea0-7266152b8c58](https://github.com/user-attachments/assets/b13979ad-d3f5-44cd-b921-b82283829091)" />
]**

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Brute Force | T1110 |
| Credential Stuffing | T1110.004 |
| Network Service Discovery | T1046 |
| Valid Accounts: Local | T1078.003 |

---

## Tools Used

`Microsoft Azure` `Microsoft Sentinel` `KQL` `Azure NSG` `Defender for Cloud` `MITRE ATT&CK` `AbuseIPDB`

---

## Key Takeaway

> *Any internet-exposed VM will be attacked within minutes — not hours. The question isn't if, it's how fast you detect and respond.*

---

*Lab conducted on personally owned Azure infrastructure.*
