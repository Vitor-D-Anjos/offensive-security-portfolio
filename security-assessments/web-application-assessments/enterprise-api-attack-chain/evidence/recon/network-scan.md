# Network Scan — Initial Reconnaissance

**Date:** May 4, 2026  
**Time:** T+0h to T+0.5h  
**Tool:** nmap 7.94  
**Command:** `nmap -p- -sS -sV -sC -A -oA scan_results <REDACTED_TARGET_IP>`

---

## Target Verification

**Hosts file entry:**

```text
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
<REDACTED_IP>   target-app.local
```

## Ping test:

```
$ ping -c3 target-app.local
PING target-app.local (<REDACTED_IP>) 56(84) bytes of data.
64 bytes from <REDACTED_IP>: icmp_seq=1 ttl=61 time=2.95 ms
64 bytes from <REDACTED_IP>: icmp_seq=2 ttl=61 time=2.37 ms
64 bytes from <REDACTED_IP>: icmp_seq=3 ttl=61 time=2.53 ms

--- target-app.local ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 2.369/2.614/2.945/0.242 ms
```

## Scan Results

```
Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-04 20:57 UTC
Nmap scan report for target-app.local (<REDACTED_IP>)
Host is up (0.0026s latency).
Not shown: 65532 closed tcp ports (reset)

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 <REDACTED> (ECDSA)
|_  256 <REDACTED> (ED25519)

3389/tcp open  ms-wbt-server xrdp

8090/tcp open  http       Node.js Express framework
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-title: Error

1337/tcp open  http       Node.js Express framework
|_http-title: Authentication Service

Device type: general purpose
Running: Linux
OS details: Linux (Ubuntu-based)
Network Distance: 3 hops

TRACEROUTE (using port 22/tcp)
HOP RTT     ADDRESS
1   0.04 ms <REDACTED_GATEWAY>
2   ...
3   2.81 ms target-app.local (<REDACTED_IP>)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.56 seconds
```

## Key Observations

1. **Three services identified:**
   - Port 22: SSH (not targeted — out of scope)
   - Port 8090: Primary web application (Express.js)
   - Port 1337: Authentication service (Express.js)

2. **CORS policy** on port 8090 allows all methods (`GET POST PUT DELETE OPTIONS PATCH`)

3. Both HTTP services return **non-standard default responses** (API-first architecture)

4. **No TLS/SSL** detected on web ports — HTTP only, no HTTPS
