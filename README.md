# OffSec Proving Grounds Practice - Write-up Portfolio

## 📌 Overview
This repository contains detailed write-ups for OffSec Proving Grounds Practice machines. Each write-up follows a structured methodology from reconnaissance to privilege escalation, demonstrating practical penetration testing skills in real-world scenarios.

## 🎯 Purpose
- Document learning progress and technical understanding
- Create a portfolio for junior penetration tester positions
- Share knowledge with the security community
- Develop systematic testing methodology

## 🏆 Completed Machines

### Linux Machines
| Machine | Difficulty | Key Skills | Root Time |
|---------|------------|------------|-----------|
| **law** | Easy | Web App RCE, CVE-2022-35914, Reverse Shell | ~1 hour |
| **LazySysAdmin** | Easy | SMB Enumeration, Password Cracking, sudo Abuse | ~45 mins |

### Windows Machines
| Machine | Difficulty | Key Skills | Domain Admin Time |
|---------|------------|------------|-------------------|
| **vault** | Intermediate | LLMNR Poisoning, NTLM Relay, Token Impersonation | ~2.5 hours |
| **Heist** | Intermediate | Kerberoasting, GMSA Abuse, SeRestorePrivilege | ~3 hours |
| **Access** | Hard | Kerberoasting, SPN Scanning, SeManageVolumePrivilege | ~4 hours |

## 🔧 Methodology
Each write-up follows this systematic approach:

### 1. Reconnaissance
- **Nmap Scanning**: Comprehensive port scanning with service detection
- **Directory Enumeration**: Discovering web paths and exposed resources
- **SMB/SQL Enumeration**: Identifying network services and shares

### 2. Vulnerability Assessment
- **Manual Testing**: Business logic flaws and misconfigurations
- **Automated Tools**: Using appropriate scanners for specific services
- **Credential Testing**: Default/weak credentials and password reuse

### 3. Initial Access
- **Web Application Attacks**: RCE, SQLi, file upload vulnerabilities
- **Service Exploitation**: SMB, SQL, RDP misconfigurations
- **Credential Access**: Password cracking, hash dumping

### 4. Privilege Escalation
- **Linux**: sudo misconfigurations, SUID binaries, kernel exploits
- **Windows**: Token privileges (SeRestore, SeManageVolume), GPO misconfigurations
- **Active Directory**: Kerberoasting, AS-REP Roasting, BloodHound analysis

### 5. Post-Exploitation
- **Lateral Movement**: Pass-the-hash, token manipulation
- **Domain Persistence**: Golden tickets, shadow copy creation
- **Data Exfiltration**: Credential harvesting, sensitive file extraction

## 🛠️ Tools Used
- **Recon**: Nmap, Gobuster, Dirb, ffuf, smbmap, enum4linux
- **Exploitation**: Metasploit, Evil-WinRM, Impacket, Responder
- **Password Attacks**: Hashcat, John the Ripper
- **AD Enumeration**: BloodHound, PowerView, ldapsearch
- **Privilege Escalation**: linpeas, winpeas, SeBackupPrivilege scripts

## 📚 Learning Outcomes

### Technical Skills
1. **Active Directory Attacks**: Mastered Kerberoasting, LLMNR poisoning, NTLM relay
2. **Privilege Escalation**: Applied Windows token privilege abuse (SeRestore, SeManageVolume)
3. **Web Application Testing**: Identified and exploited RCE vulnerabilities
4. **Password Cracking**: Successfully cracked NTLM, NetNTLMv2 hashes

### Professional Skills
1. **Documentation**: Created detailed, reproducible write-ups
2. **Methodology**: Developed systematic testing approach
3. **Problem Solving**: Overcame obstacles with creative solutions
4. **Time Management**: Completed machines within reasonable timeframes

## 🚀 How to Use This Repository
1. **For Learning**: Follow the write-ups to understand attack vectors
2. **For Reference**: Use as a cheatsheet for similar scenarios
3. **For Interviews**: Demonstrate practical penetration testing experience

## 🔗 Connect
- **LinkedIn**: [linkedin.com/in/james-sec](https://linkedin.com/in/james-sec)
- **GitHub**: [github.com/0x5A65726F677275](https://github.com/0x5A65726F677275)
- **PG Profile**: [OffSec Profile](https://portal.offsec.com/profile/)

## ⚠️ Disclaimer
These write-ups are for educational purposes only. All machines were tested in authorized lab environments (OffSec Proving Grounds). Unauthorized testing of systems you don't own is illegal and unethical.

## 📄 License
MIT License - See LICENSE file for details
