# Network Topology & Attack Flow Diagrams
## Multi-Tier Infrastructure Compromise Assessment

**Document Purpose:** Visual representation of network architecture and attack progression  
**Created:** October 2025  
**Classification:** CONFIDENTIAL

---

## Diagram 1: Network Topology Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INTERNET / ATTACKER                        │
│                         Kali Linux (10.50.100.5)                    │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 │ Port Scanning
                                 │ SMB Enumeration
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    EXTERNAL NETWORK (10.50.100.0/24)                │
│                              DMZ / Perimeter                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────┐         ┌──────────────────────────┐   │
│  │  gateway.corp.local     │         │  webapps.corp.local      │   │
│  │  10.50.100.10           │         │  10.50.100.20            │   │
│  ├─────────────────────────┤         ├──────────────────────────┤   │
│  │ • SMB (445) ❌          │         │ • HTTP (80) ❌          │   │
│  │ • Anonymous Access      │         │ • MySQL (3306) ❌        │   │
│  │ • Credentials Exposed   │         │ • Git Exposed ❌         │   │
│  └─────────────────────────┘         └──────────────────────────┘   │
│           │                                      │                  │
│           │ Credential                           │ eth0             │
│           │ Harvest ✅                           │                  │
│           │                                      │                  │
└───────────┴──────────────────────────────────────┴──────────────────┘
                                                   │
                      ┌────────────────────────────┘
                      │ eth1 (Dual-Homed)
                      │ Network Pivot ✅
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   INTERNAL NETWORK (172.16.50.0/24)                 │
│                      Trusted / Corporate Network                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────┐         ┌──────────────────────────┐   │
│  │ gateway-internal        │         │ vault.corp.internal      │   │
│  │ 172.16.50.5             │         │ 172.16.50.15             │   │
│  ├─────────────────────────┤         ├──────────────────────────┤   │
│  │ • SSH (22)              │         │ • SSH (22) ❌           │   │
│  │ • RPC (111)             │         │ • Weak Auth ❌          │   │
│  │ • Not Exploited         │         │ • CVE-2025-32463 ❌     │   │
│  └─────────────────────────┘         └──────────────────────────┘   │
│                                               │                     │
│                                               │ SSH Brute Force ✅  │
│                                               │ Privilege Esc ✅    │
│                                               ▼                     │
│                                       🔴 ROOT ACCESS                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

LEGEND:
─────────
• ❌ = Vulnerability exploited
• ✅ = Successful exploitation/access
• 🔴 = Critical compromise (root/admin)
• │ = Network connection/traffic flow
```

---

## Diagram 2: Attack Progression Timeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ATTACK TIMELINE                                  │
└──────────────────────────────────────────────────────────────────────────┘

T+00:00  [RECONNAISSANCE]
         │
         ├─► Nmap Port Scan (gateway.corp.local)
         │   └─► Discovered: SMB (445), ports 1234, 5678, 9101
         │
         └─► Nmap Port Scan (webapps.corp.local)
             └─► Discovered: HTTP (80), MySQL (3306)

T+00:15  [INITIAL ACCESS]
         │
         ├─► SMB Anonymous Access (gateway.corp.local)
         │   └─► Retrieved: credentials.txt, endpoint.txt
         │       └─► Obtained: robert_admin:SecureP@ss2024 ✅
         │
         └─► Git Repository Exposure (webapps.corp.local)
             └─► Extracted: Source code, database config

T+00:30  [EXPLOITATION]
         │
         ├─► Web Admin Authentication
         │   └─► Login: robert_admin:SecureP@ss2024 ✅
         │
         ├─► Web Shell Upload
         │   └─► Uploaded: webshell.php via file manager
         │
         └─► Reverse Shell
             └─► Obtained: www-data shell ✅

T+01:00  [POST-EXPLOITATION]
         │
         ├─► System Enumeration
         │   └─► Discovered: Dual-homed host (eth0 + eth1)
         │
         ├─► Database Access
         │   └─► MySQL: root (no password) ✅
         │       └─► Extracted: User hashes
         │
         └─► Meterpreter Upgrade
             └─► Established: Meterpreter session ✅

T+01:30  [CREDENTIAL HARVESTING]
         │
         ├─► MySQL User Table Dump
         │   └─► Retrieved: admin_db, svc_backup hashes
         │
         └─► Password Cracking (Hashcat)
             └─► Cracked: svc_backup:SecureP@ss2024 ✅

T+02:00  [LATERAL MOVEMENT]
         │
         ├─► Network Pivoting
         │   └─► Autoroute: 172.16.50.0/24 ✅
         │
         ├─► Internal Network Scan
         │   └─► Discovered: 172.16.50.15 (vault.corp.internal)
         │
         └─► Port Forwarding Setup
             └─► Forward: SSH port 22 → localhost:2222 ✅

T+02:45  [TARGET COMPROMISE]
         │
         └─► SSH Brute Force (vault.corp.internal)
             └─► Cracked: admin_vault:Welcome2024! ✅
                 └─► Obtained: User-level SSH access ✅

T+03:15  [PRIVILEGE ESCALATION]
         │
         ├─► Vulnerability Identification
         │   └─► Found: CVE-2025-32463 (sudo 1.9.16p2)
         │
         ├─► Exploit Development
         │   └─► Compiled: Custom privilege escalation exploit
         │
         └─► Root Access
             └─► Executed: sudo --chroot exploit
                 └─► 🔴 ROOT ACCESS ACHIEVED ✅

═══════════════════════════════════════════════════════════════════════════
TOTAL TIME: 3 hours 15 minutes (active exploitation)
SYSTEMS COMPROMISED: 3/3 (100%)
PRIVILEGE LEVEL: root/administrator on all systems
═══════════════════════════════════════════════════════════════════════════
```

---

## Diagram 3: Data Flow & Exploitation Chain

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    EXPLOITATION FLOW DIAGRAM                            │
└─────────────────────────────────────────────────────────────────────────┘

    ATTACKER                    TARGET SYSTEMS                  OUTCOME
    ────────                    ──────────────                  ───────

      (1)                                                     Credentials
       │                                                      Discovered
       ├──► SMB Anonymous ──────────────────► gateway.corp ──────────┐
       │      Access                          (10.50.100.10)         │
       │                                                             │
       │                                                             ▼
       │                                                    robert_admin:
       │                                                    SecureP@ss2024
       │                                                              │
      (2)                                                             │
       │◄─────────────────────────────────────────────────────────────┘
       │
       ├──► Web Admin ─────────────────────► webapps.corp ──────────┐
       │      Login                           (10.50.100.20)        │
       │                                      [Wolf CMS]            │
       │                                                            │
      (3)                                                           │
       │                                                            │
       ├──► File Upload ────────────────────► webapps.corp          │
       │      (webshell.php)                   [/public/]           │
       │                                                            │
       │                                                            ▼
       │                                                         Web Shell
       │◄──────────────────────────────────────────────────────  Deployed
       │                                                            │
      (4)                                                           │
       │                                                            │
       ├──► HTTP Request ───────────────────► webapps.corp          │
       │      (trigger shell)                  [webshell.php]       │
       │                                                            │
       │◄────────────────────────────────────────────────────────── │
       │                   Reverse Shell (www-data)                 │
       │                                                            │
      (5)                                                           │
       │                                                            │
       ├──► Port Forward ───────────────────► MySQL                 │
       │      Setup                            (localhost:3306)     │
       │                                                            │
       ├──► Database ────────────────────────► MySQL root           │
       │      Access                           (no password)        │
       │                                                            │
       │◄────────────────────────────────────────────────────────── │
       │              Password Hashes Extracted                     │
       │              (admin_db, svc_backup)                        │
       │                                                            │
      (6)                                                           │
       │                                                            │
       ├──► Hashcat ─────────────────────────► Local Cracking       │
       │      Cracking                          [Offline]           │
       │                                                            │
       │◄────────────────────────────────────────────────────────── │
       │           svc_backup:SecureP@ss2024                        │
       │                                                            │
      (7)                                                           │
       │                                                            │
       ├──► Network ─────────────────────────► Meterpreter          │
       │      Pivoting                          [autoroute]         │
       │                                                            │
       ├──► Port Scan ───────────────────────► Internal Network     │
       │                                        (172.16.50.0/24)    │
       │                                                            │
       │◄────────────────────────────────────────────────────────── │
       │          vault.corp.internal discovered                    │
       │          (172.16.50.15)                                    │
       │                                                            │
      (8)                                                           │
       │                                                            │
       ├──► SSH Brute ───────────────────────► vault.corp.internal  │
       │      Force                             (172.16.50.15)      │
       │      [Hydra]                                               │
       │                                                            │
       │◄────────────────────────────────────────────────────────── │
       │      admin_vault:Welcome2024!                              │
       │      [SSH User Access]                                     │
       │                                                            │
      (9)                                                           │
       │                                                            │
       ├──► CVE-2025-32463 ──────────────────► vault.corp.internal  │
       │      Exploit                           [sudo 1.9.16p2]     │
       │      [Privilege Esc]                                       │
       │                                                            │
       │◄────────────────────────────────────────────────────────── │
       │                  🔴 ROOT SHELL                             │
       │                  uid=0(root)                               │
       │                  COMPLETE COMPROMISE                       │
       │                                                            │
       ▼
  MISSION COMPLETE
  ═══════════════
  3 Systems Owned
  Root Access All
```

---

## Diagram 4: Network Segmentation Failures

```
┌──────────────────────────────────────────────────────────────────────────┐
│              NETWORK SEGMENTATION ANALYSIS                               │
│         (Showing Security Boundary Failures)                             │
└──────────────────────────────────────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════╗
║                          INTERNET                                     ║
║                     (Untrusted Network)                               ║
╚═══════════════════════════╤═══════════════════════════════════════════╝
                            │
                            │ ❌ NO EXTERNAL FIREWALL
                            │ ❌ NO IDS/IPS
                            │
                            ▼
╔═══════════════════════════════════════════════════════════════════════╗
║                   DMZ / EXTERNAL NETWORK                              ║
║                      (10.50.100.0/24)                                 ║
║                    ❌ Minimal Security                                ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  gateway.corp.local          webapps.corp.local                       ║
║  └─ SMB Exposed              └─ Web App Exposed                       ║
║     └─ Anonymous Access         └─ MySQL Exposed                      ║
║                                    └─ Dual-Homed ⚠️                   ║
║                                                                       ║
╚══════════════════════════════════╤════════════════════════════════════╝
                                   │
                                   │ ❌ NO INTERNAL FIREWALL
                                   │ ❌ NO ACCESS CONTROLS  
                                   │ ❌ DIRECT ROUTING ALLOWED
                                   │ ⚠️  Pivoting Possible
                                   │
                                   ▼
╔═══════════════════════════════════════════════════════════════════════╗
║                     INTERNAL NETWORK                                  ║
║                      (172.16.50.0/24)                                 ║
║                  ❌ No Additional Security                            ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  gateway-internal            vault.corp.internal                      ║
║  └─ SSH/RPC                  └─ SSH Accessible                        ║
║                                 └─ Weak Passwords                     ║
║                                    └─ Unpatched sudo                  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

SECURITY BOUNDARY FAILURES:
═══════════════════════════
❌ No perimeter firewall
❌ No DMZ to Internal firewall
❌ No network segmentation
❌ No traffic filtering
❌ No intrusion detection
❌ Direct routing between all networks
⚠️  Single compromise = Full access

RECOMMENDED ARCHITECTURE:
════════════════════════

Internet
   │
[Firewall #1] ◄── External Perimeter
   │
  DMZ
   │
[Firewall #2] ◄── Internal Boundary
   │
Internal Net
   │
[Firewall #3] ◄── Critical Assets
   │
Secure Vault
```

---

## Diagram 5: Credential Flow & Reuse

```
┌──────────────────────────────────────────────────────────────────────────┐
│                 CREDENTIAL HARVESTING & REUSE MAP                        │
└──────────────────────────────────────────────────────────────────────────┘

                        CREDENTIAL DISCOVERY
                        ═══════════════════

┌─────────────────────┐
│  SMB Share          │
│  (Anonymous)        │
│  credentials.txt    │
└──────┬──────────────┘
       │
       ├──► robert_admin:SecureP@ss2024 ───────┐
       │                                       │
       └──► /admin/console endpoint info       │
                                               │
┌──────────────────────────────────────────────┼──────────────────────┐
│                                              ▼                      │
│                          ┌─────────────────────────────┐            │
│                          │ webapps.corp.local          │            │
│                          │ Wolf CMS Admin Panel        │            │
│                          └─────────────┬───────────────┘            │
│                                        │                            │
│                     File Upload Access │                            │
│                                        ▼                            │
│                          ┌─────────────────────────────┐            │
│                          │  Web Shell Deployed         │            │
│                          │  www-data shell             │            │
│                          └─────────────┬───────────────┘            │
│                                        │                            │
│                                        │                            │
│                     Database Access    │                            │
│                                        ▼                            │
│                          ┌─────────────────────────────┐            │
│                          │  MySQL root                 │            │
│                          │  (no password) ❌          │             │
│                          └─────────────┬───────────────┘            │
│                                        │                            │
│                     SELECT user,pass   │                            │
│                                        ▼                            │
│                          ┌─────────────────────────────┐            │
│                          │  Password Hashes:           │            │
│                          │  • admin_db (hash)          │            │
│                          │  • svc_backup (hash) ✅    │             │
│                          └─────────────┬───────────────┘             │
│                                        │                             │
│                         Hashcat Crack  │                             │
│                                        ▼                             │
│                          ┌─────────────────────────────┐             │
│                          │ svc_backup:                 │             │
│                          │ SecureP@ss2024 ✅          │             │
│                          └─────────────┬───────────────┘             │
│                                        │                             │
│                          NOT USED      │ (Same as robert_admin!)     │
│                          (same pass)   │                             │
│                                        │                             │
└────────────────────────────────────────┼─────────────────────────────┘
                                         │
                  ┌──────────────────────┘
                  │
                  │ Network Pivot to 172.16.50.0/24
                  │
                  ▼
        ┌─────────────────────────┐
        │ vault.corp.internal     │
        │ 172.16.50.15           │
        └──────────┬──────────────┘
                   │
      SSH Brute    │ (Different password needed)
      Force        │
                   ▼
        ┌─────────────────────────┐
        │ admin_vault:            │
        │ Welcome2024! ✅        │
        └──────────┬──────────────┘
                   │
                   │ User-level access
                   │
                   ▼
        ┌─────────────────────────┐
        │ CVE-2025-32463          │
        │ Privilege Escalation    │
        └──────────┬──────────────┘
                   │
                   ▼
        ┌─────────────────────────┐
        │ 🔴 ROOT ACCESS          │
        │ uid=0(root) gid=0(root) │
        └─────────────────────────┘

CREDENTIAL REUSE ANALYSIS:
═════════════════════════
✅ robert_admin password reused for:
   • SMB share documentation
   • Web CMS admin panel

✅ SecureP@ss2024 found in:
   • SMB credentials.txt
   • MySQL svc_backup hash
   • Indicates weak password policy

❌ admin_vault required brute force
   • No credential reuse
   • But weak password (Welcome2024!)

LESSON: Password reuse enabled
rapid lateral movement across systems
```

---

## Diagram 6: MITRE ATT&CK Heat Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│           MITRE ATT&CK TECHNIQUES USED (Heat Map)                        │
│                                                                          │
│  █████ = 5+ techniques    ████ = 3-4 techniques    ███ = 1-2 techniques  │
└──────────────────────────────────────────────────────────────────────────┘

TACTIC                          TECHNIQUES USED              INTENSITY
─────────────────────────────────────────────────────────────────────────

Reconnaissance (TA0043)              3 techniques               ███
├─ T1046: Network Service Discovery
├─ T1087.002: Account Discovery  
└─ T1592.002: Gather Victim Host Info

Initial Access (TA0001)              3 techniques               ███
├─ T1133: External Remote Services
├─ T1078.003: Valid Accounts
└─ T1190: Exploit Public-Facing App

Execution (TA0002)                   3 techniques               ███
├─ T1059.004: Unix Shell
├─ T1059.006: Python
└─ T1203: Exploitation for Execution

Persistence (TA0003)                 2 techniques               ██
├─ T1505.003: Web Shell
└─ T1098: Account Manipulation

Privilege Escalation (TA0004)        2 techniques               ██
├─ T1068: Exploitation for Priv Esc
└─ T1548.003: Sudo Abuse

Defense Evasion (TA0005)             2 techniques               ██
├─ T1070.006: Timestomp
└─ T1027: Obfuscated Files

Credential Access (TA0006)           7 techniques              █████
├─ T1110.001: Password Guessing
├─ T1110.002: Password Cracking
├─ T1555: Credentials from Stores
├─ T1552.001: Credentials in Files
├─ T1552.004: Private Keys
├─ T1003.008: OS Credential Dumping
└─ T1589.001: Gather Credentials

Discovery (TA0007)                   7 techniques              █████
├─ T1082: System Information Discovery
├─ T1083: File and Directory Discovery
├─ T1087.001: Local Account Discovery
├─ T1018: Remote System Discovery
├─ T1046: Network Service Discovery
├─ T1049: Network Connections Discovery
└─ T1057: Process Discovery

Lateral Movement (TA0008)            3 techniques               ███
├─ T1021.004: SSH
├─ T1090.001: Internal Proxy
└─ T1563: Session Hijacking

Collection (TA0009)                  2 techniques               ██
├─ T1005: Data from Local System
└─ T1039: Data from Network Share

Command & Control (TA0011)           3 techniques               ███
├─ T1071.001: Web Protocols
├─ T1573.001: Encrypted Channel
└─ T1095: Non-Application Layer

Impact (TA0040)                      3 techniques               ███
├─ T1485: Data Destruction (capability)
├─ T1486: Data Encrypted (capability)
└─ T1529: System Shutdown (capability)

═════════════════════════════════════════════════════════════════════════
TOTAL: 40 TECHNIQUES ACROSS 12 TACTICS
HIGHEST ACTIVITY: Credential Access (7) & Discovery (7)
ATTACK SOPHISTICATION: Medium-High (multi-stage, pivoting)
═════════════════════════════════════════════════════════════════════════
```

