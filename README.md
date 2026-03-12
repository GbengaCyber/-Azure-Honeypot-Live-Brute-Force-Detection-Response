# 🍯 Azure Honeypot — Live Brute Force Attack Detection & Response

> **Real-world SOC incident:** A deliberately exposed Azure VM was used as a honeypot to capture live attack telemetry. Within minutes of deployment, automated threat actors launched a sustained brute force campaign. This documents the full incident lifecycle — detection, analysis, containment, and hardening.

---

## 📋 Project Overview

| Field | Details |
|---|---|
| **Platform** | Microsoft Azure + Microsoft Sentinel (SIEM) |
| **VM Hostname** | `soclab` |
| **Attack Type** | Brute Force / Credential Stuffing |
| **Auth Protocol Targeted** | NTLM (SMB / RDP) |
| **Attacker IPs** | `185.156.73.x` · `92.63.197.x` |
| **Detection Tool** | KQL — Microsoft Sentinel |
| **Incident Status** | ✅ Contained — No Compromise Confirmed |

---

## 🎯 Objective

Deploy a purposely internet-exposed Azure VM with a **honeypot account** to:

- Observe real-world attack patterns against cloud infrastructure
- Practice live threat detection using **KQL in Microsoft Sentinel**
- Execute an end-to-end **SOC incident response workflow**
- Demonstrate hardening techniques using Azure-native security tools

---

## 🪤 Phase 1 — Honeypot Setup

A fresh Azure Virtual Machine (`soclab`) was deployed with:

- **Public IP exposed** to the internet (no Bastion, no JIT)
- **RDP port 3389 open** inbound via default NSG rules
- **Honeypot account created** with a common, easily-guessable username to attract automated scanners
- **Microsoft Sentinel connected** to the VM's Log Analytics Workspace to capture all authentication events

> 💡 Internet-facing VMs are typically discovered and attacked by automated bots **within minutes** of deployment — this experiment confirmed exactly that.

---

## 🚨 Phase 2 — Attack Detected

### KQL Queries Used for Detection

**Query 1 — Device Logon Events:**
```kql
DeviceLogonEvents
| where DeviceName == "soclab"
```

**Query 2 — Security Events (Authentication Detail):**
```kql
SecurityEvent
| where Computer == "soclab"
| project TimeGenerated, Account, IpAddress, LocationInformation,
          AccountType, AuthenticationPackageName


```

### Results — Evidence of Brute Force


The queries returned **1,000+ events within 24 hours**, all bearing the hallmarks of an automated credential stuffing campaign:

| TimeGenerated (UTC) | Account Targeted | Source IP | Auth Protocol |
|---|---|---|---|
| 3/12/2026, 2:22:25 PM | soclab\asc | 185.156.73.173 | NTLM |
| 3/12/2026, 2:22:25 PM | soclab\administrator | 185.156.73.59 | NTLM |
| 3/12/2026, 2:22:25 PM | soclab\edu | 92.63.197.9 | NTLM |
| 3/12/2026, 2:22:24 PM | soclab\administrator | 92.63.197.9 | NTLM |
| 3/12/2026, 2:22:24 PM | soclab\mkt | 185.156.73.24 | NTLM |
| 3/12/2026, 2:22:24 PM | soclab\ws7 | 92.63.197.69 | NTLM |
| 3/12/2026, 2:22:24 PM | soclab\paulh | 185.156.73.173 | NTLM |
| 3/12/2026, 2:22:24 PM | soclab\nati | 92.63.197.69 | NTLM |

<img width="1000" height="600" alt="image" src="https://github.com/user-attachments/assets/fb27be3b-d8e6-47cf-8a83-cff2ff34d2d3" />


### Attack Indicators

| Indicator | Observation | Significance |
|---|---|---|
| **Millisecond timestamps** | Events within 1–100ms of each other | Definitively automated — not human |
| **NTLM authentication** | All attempts use NTLM | Targeting SMB/RDP attack surface |
| **Username enumeration** | Common names: admin, edu, mkt, ws7 | Credential stuffing wordlist in use |
| **Multiple IPs, same subnet** | `185.156.73.x` and `92.63.197.x` | Coordinated botnet infrastructure |
| **Volume** | 1,000+ events in 24 hours | Sustained automated campaign |

---

## 🧠 Phase 3 — Analysis & Threat Intelligence

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Credential Access | Credential Stuffing | T1110.004 |
| Discovery | Network Service Discovery | T1046 |
| Initial Access | Valid Accounts: Local Accounts | T1078.003 |

### Attacker Infrastructure (OSINT)

| IP Range | Classification | Confidence |
|---|---|---|
| `185.156.73.x` | Known malicious — botnet infrastructure | HIGH |
| `92.63.197.x` | Known malicious — automated scanner | HIGH |

Both ranges confirmed via **AbuseIPDB**, **Shodan**, and **VirusTotal** as associated with coordinated scanning and brute force campaigns.

---

## ⚡ Phase 4 — Incident Response

Upon confirming the brute force attack, I immediately sprang into action:

### Step 1 — Isolate the Device

The VM was **network-isolated** via NSG to prevent any potential lateral movement while the investigation continued. All inbound traffic was blocked at the network layer — equivalent to pulling the network cable on a physical machine.

### Step 2 — Hunt for Successful Logins

While the device was isolated, I ran targeted KQL queries to determine if any brute force attempt had succeeded:

```kql
SecurityEvent
| where Computer == "soclab"
| where EventID == 4624  // Successful logon
| where IpAddress has_any ("185.156.73", "92.63.197")
| project TimeGenerated, Account, IpAddress, LogonType

<img width="976" height="387" alt="image" src="https://github.com/user-attachments/assets/c2d17203-0249-4aae-915a-3b9148fc2814" />

```

```kql
// Check sign-in logs for any anomalous successful auth
SecurityEvent
| where Computer == "soclab"
| where EventID == 4624
| where TimeGenerated > ago(24h)
| summarize SuccessfulLogons = count() by Account, IpAddress
| order by SuccessfulLogons desc

<img width="1200" height="800" alt="image" src="https://github.com/user-attachments/assets/d02dfc17-9174-4085-ac01-b613c791c1f3" />

```

> ✅ **Result: No successful logons from attacker IPs were found. Zero compromise confirmed.**

### Step 3 — Confirm Attack Volume Post-Isolation

```kql
SecurityEvent
| where Computer == "soclab"
| where EventID == 4625  // Failed logon
| where TimeGenerated > ago(1h)
| summarize AttemptsBlocked = count() by IpAddress, bin(TimeGenerated, 5m)
| order by AttemptsBlocked desc
```

---

## 🔒 Phase 5 — Hardening & Remediation

### NSG Rules Applied

After confirming no compromise, the VM was brought back online with strict NSG rules:

| Priority | Rule Name | Port | Source | Action |
|---|---|---|---|---|
| 300 | RDP | 3389 | `[My Home IP]/32` | ✅ Allow |
| 311 | Deny_Public_IP_Access | 3389 | Any | ❌ Deny |
| 65000 | AllowVnetInBound | Any | VirtualNetwork | ✅ Allow |
| 65500 | DenyAllInBound | Any | Any | ❌ Deny |

**Only my specific home IP can reach RDP. The entire internet is blocked.**

### Full Hardening Checklist

| Control | Implementation | Status |
|---|---|---|
| Restrict RDP to trusted IP | NSG source IP allowlist (`/32`) | ✅ Done |
| Deny-all fallback rule | Priority 311 `Deny_Public_IP_Access` | ✅ Done |
| Block legacy NTLM auth | Disabled NTLM where possible | ✅ Done |
| Enable MFA | Azure AD / Entra ID MFA enforced | ✅ Done |
| Account lockout policy | Lockout after 5 failed attempts | ✅ Done |
| Enable Defender for Cloud | Microsoft Defender for Cloud activated | ✅ Done |
| Sentinel analytics rules | Custom alerts for brute force patterns | ✅ Done |

---

## 📊 Phase 6 — Recommendations

### Immediate (Day 1)
- **Never expose RDP (3389) to the public internet** — use Azure Bastion or JIT VM Access instead
- **Apply IP allowlisting** on any management port as a minimum baseline
- **Enable Microsoft Defender for Cloud** on all Azure subscriptions from day one

### Short-Term (Week 1)
- **Deploy Azure Bastion** — browser-based RDP/SSH with no public IP required
- **Enable Just-in-Time (JIT) VM Access** — ports open only on-demand with approval workflow
- **Enforce MFA** on all accounts with access to cloud resources
- **Set account lockout policies** — 5 failed attempts, 30-minute lockout minimum

### Long-Term (Ongoing)
- **Connect all VMs to Microsoft Sentinel** — centralized SIEM visibility across the estate
- **Create custom KQL analytics rules** for brute force pattern detection
- **Integrate threat intelligence feeds** (Microsoft TI, AbuseIPDB) for automated IP reputation checks
- **Run regular honeypot exercises** to capture evolving attacker TTPs and test detection capabilities
- **Review NSG effective security rules monthly** — rule bloat is a real risk over time

---

## 🛠️ Tools & Technologies Used

| Tool | Purpose |
|---|---|
| Microsoft Azure | VM deployment, NSG, network infrastructure |
| Microsoft Sentinel | SIEM — log aggregation, KQL threat hunting |
| KQL (Kusto Query Language) | Detection queries, sign-in log analysis |
| Azure Network Security Groups | Network isolation, IP allowlisting |
| Microsoft Defender for Cloud | Vulnerability assessment, security posture |
| MITRE ATT&CK Framework | TTP mapping and threat classification |
| AbuseIPDB / Shodan / VirusTotal | OSINT — attacker IP reputation analysis |

---

## 📁 Repository Structure

```
azure-honeypot-soc-lab/
│
├── README.md                  # This file — full incident writeup
├── kql-queries/
│   ├── detection.kql          # Initial brute force detection queries
│   ├── hunt-successful-logins.kql  # Post-incident compromise check
│   └── post-hardening-verify.kql  # Confirm blocks are working
├── screenshots/
│   ├── sentinel-attack-logs.png   # Live attack data in Sentinel
│   ├── nsg-before.png             # NSG rules before hardening
│   └── nsg-after.png              # NSG rules after hardening
└── mitre-attack-mapping.md    # Full TTP breakdown
```

---

## 🔑 Key Takeaways

> **"A VM exposed to the internet will be attacked within minutes — not hours, not days. Minutes."**

1. **Attackers are automated and relentless** — bots scan the entire IPv4 internet continuously
2. **NTLM on public internet = immediate attack surface** — always disable or restrict
3. **KQL is an extremely powerful detection tool** — a few lines can surface a full attack campaign
4. **Azure's native security stack is comprehensive** — Sentinel + Defender + NSG + Bastion covers the full kill chain
5. **Honeypots are one of the best learning tools** in cloud security — real attacks, real telemetry, real skills

---

*Built as part of a hands-on Azure cloud security lab. All activity conducted on personally owned infrastructure.*
