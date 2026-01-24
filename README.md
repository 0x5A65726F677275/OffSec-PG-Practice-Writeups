# OffSec Proving Grounds Practice: Technical Write-up Portfolio

## Overview
A curated collection of detailed technical write-ups documenting the successful compromise of multiple OffSec Proving Grounds Practice machines. This portfolio demonstrates systematic penetration testing methodology applied across diverse environments, from simple Linux systems to complex Active Directory domains.

## Technical Objectives
- Document comprehensive attack chains from reconnaissance to full compromise
- Establish reproducible testing methodologies for various attack vectors
- Demonstrate proficiency with enterprise security assessment tools and techniques
- Create reference material for complex Active Directory attack scenarios

## Completed Engagements

### Linux Environment Assessments

| Machine | Difficulty | Primary Attack Vectors | Compromise Time | Key Findings |
|---------|------------|------------------------|-----------------|--------------|
| **law** | Easy | CVE-2022-35914 (GLPI RCE), Web Application Exploitation | 1 hour | Unauthenticated command injection via third-party library |
| **LazySysAdmin** | Easy | SMB Credential Enumeration, Weak Password Policy, Sudo Misconfiguration | 45 minutes | Default credentials, writable SMB shares, unrestricted sudo privileges |

### Windows Active Directory Assessments

| Machine | Difficulty | Attack Methodology | Domain Admin Time | Critical Vulnerabilities |
|---------|------------|---------------------|-------------------|--------------------------|
| **vault** | Intermediate | LLMNR/NBT-NS Poisoning, NetNTLMv2 Relay, Token Impersonation | 2.5 hours | Unsecured LLMNR, Weak Password "SecureHM", SeRestorePrivilege abuse |
| **Heist** | Intermediate | GMSA Hash Extraction, Pass-the-Hash, SeRestorePrivilege Exploitation | 3 hours | GMSA password exposure, NetNTLMv2 hash capture, Privilege escalation via token manipulation |
| **Access** | Hard | Kerberoasting, SPN Enumeration, SeManageVolumePrivilege Abuse | 4 hours | Service account with excessive privileges, Kerberos ticket exposure, Volume maintenance privilege escalation |

## Testing Methodology Framework

### Phase 1: Reconnaissance and Discovery
- **Network Enumeration**: Comprehensive port scanning with service fingerprinting using Nmap aggressive scans (-sC -sV -A)
- **Service Identification**: Active Directory detection via LDAP (389/636), Kerberos (88), and SMB (445) analysis
- **Web Application Mapping**: Directory brute-forcing with Gobuster/Dirb, parameter analysis, and technology stack identification

### Phase 2: Vulnerability Assessment
- **Credential Attack Surface**: Identification of default credentials, password reuse patterns, and weak authentication mechanisms
- **Service Configuration Analysis**: Examination of SMB share permissions, RDP security settings, and web server misconfigurations
- **Active Directory Reconnaissance**: User enumeration, group membership analysis, and privilege mapping using BloodHound and PowerView

### Phase 3: Initial Compromise
- **Web Application Exploitation**: Command injection, file upload bypasses, and deserialization vulnerabilities
- **Service Authentication Bypass**: SMB null session attacks, RDP credential stuffing, and WinRM access with cracked credentials
- **Protocol Exploitation**: LLMNR/NBT-NS poisoning for credential harvesting, Kerberoasting for service account compromise

### Phase 4: Privilege Escalation
- **Linux Systems**: SUID/SGID binary analysis, cron job exploitation, kernel vulnerability assessment
- **Windows Systems**: Token privilege analysis (SeRestore, SeManageVolume, SeBackup), Group Policy Object misconfigurations
- **Active Directory**: Kerberos delegation abuse, ACL-based privilege escalation, Group Managed Service Account (GMSA) exploitation

### Phase 5: Post-Exploitation and Lateral Movement
- **Credential Harvesting**: LSASS memory dumping, registry extraction of cached credentials, NTDS.dit acquisition
- **Persistence Mechanisms**: Golden/Silver ticket creation, skeleton key implementation, scheduled task establishment
- **Domain Dominance**: Domain controller compromise, group policy modification, trust relationship exploitation

## Toolchain Proficiency

### Reconnaissance and Enumeration
- **Network Scanning**: Nmap with custom scripts for service detection and vulnerability identification
- **Web Application Testing**: Burp Suite for manual testing, FFUF for directory enumeration, SQLMap for database assessment
- **Active Directory Analysis**: BloodHound for privilege relationship mapping, ldapsearch for manual LDAP queries, PowerView for in-memory enumeration

### Exploitation and Access
- **Remote Access**: Evil-WinRM for Windows remote management, Impacket suite for protocol-level attacks
- **Credential Attacks**: Hashcat for password cracking with rule-based attacks, John the Ripper for hash analysis
- **Payload Delivery**: Custom PowerShell payloads, C2 framework integration (Sliver), and living-off-the-land techniques

### Post-Exploitation
- **Privilege Escalation**: WinPEAS/LinPEAS for automated enumeration, manual token privilege exploitation
- **Lateral Movement**: Pass-the-Hash, Overpass-the-Hash, DCOM/WMI execution, scheduled task deployment
- **Persistence**: Registry modification, service creation, WMI event subscription, startup folder manipulation

## Technical Competencies Demonstrated

### Active Directory Security Assessment
- **Kerberos Attack Techniques**: Kerberoasting (TGS-REP extraction), AS-REP Roasting (pre-authentication disabled), Golden/Silver ticket creation
- **Authentication Protocol Exploitation**: NTLM relay attacks, NetNTLMv2 hash capture and cracking, pass-the-hash techniques
- **Privilege Escalation Paths**: ACL-based privilege escalation, resource-based constrained delegation abuse, GMSA password extraction

### Windows Security Evaluation
- **Token Privilege Analysis**: Identification and exploitation of SeRestorePrivilege, SeManageVolumePrivilege, SeBackupPrivilege
- **Service Account Security**: GMSA configuration review, service principal name analysis, least privilege violation identification
- **Defense Evasion**: Living-off-the-land binary (LOLBin) utilization, AMSI bypass techniques, PowerShell Constrained Language Mode circumvention

### Web Application Security Testing
- **Remote Code Execution**: Command injection vulnerability identification and exploitation, deserialization attack execution
- **Authentication Bypass**: Session management flaws, weak credential storage, insufficient authorization checks
- **Business Logic Flaws**: IDOR (Insecure Direct Object Reference) exploitation, workflow circumvention, privilege escalation via parameter manipulation

## Professional Development Outcomes

### Technical Skill Advancement
1. **Active Directory Penetration Testing**: Developed comprehensive methodology for AD security assessment from initial access to domain dominance
2. **Privilege Escalation Techniques**: Mastered multiple Windows privilege escalation vectors including token privilege abuse and service misconfigurations
3. **Web Application Security**: Applied OWASP testing methodology to identify and exploit critical vulnerabilities in web applications
4. **Password Security Analysis**: Implemented systematic approach to credential attack including hash capture, cracking, and reuse analysis

### Methodology Development
1. **Structured Testing Approach**: Created repeatable testing frameworks for different environment types (Linux, Windows standalone, Active Directory)
2. **Documentation Standards**: Established comprehensive reporting templates including executive summaries, technical details, and remediation guidance
3. **Tool Integration**: Developed workflows for integrating multiple security tools into cohesive testing processes
4. **Time Management**: Optimized testing approaches to maximize efficiency while maintaining thorough coverage

### Problem-Solving Capabilities
1. **Obstacle Resolution**: Demonstrated ability to overcome testing barriers through alternative approaches and creative problem-solving
2. **Technical Research**: Conducted independent research on emerging vulnerabilities and exploitation techniques
3. **Adaptive Testing**: Modified testing approaches based on environmental constraints and defensive measures encountered
4. **Validation and Verification**: Implemented processes to validate findings and eliminate false positives

## Repository Utilization Guidelines

### For Security Professionals
- **Reference Material**: Use as technical reference for specific attack techniques and tool usage
- **Methodology Template**: Adapt testing methodologies for similar assessment scenarios
- **Training Resource**: Supplement security training with practical, documented examples

### For Hiring Assessment
- **Skill Verification**: Review to validate practical penetration testing capabilities
- **Methodology Evaluation**: Assess systematic approach to security testing
- **Technical Depth Analysis**: Evaluate understanding of complex security concepts and their practical application

### For Educational Purposes
- **Learning Path**: Follow documented attacks to understand vulnerability chaining and exploit development
- **Tool Familiarization**: Study command examples and tool usage patterns
- **Defensive Understanding**: Analyze attack techniques to inform defensive strategy development

## Contact and Verification
- **LinkedIn Professional Profile**: https://linkedin.com/in/james-sec
- **GitHub Repository**: https://github.com/0x5A65726F677275
- **OffSec Verification**: PG Practice completion verifiable through OffSec portal
- **Technical References**: All tools and techniques referenced are publicly documented and widely used in security assessments

## Legal and Ethical Considerations
All testing documented in this repository was conducted within authorized environments specifically designed for security training. The OffSec Proving Grounds platform provides legal environments for developing and practicing penetration testing skills. No systems outside these authorized environments were accessed or tested.

The techniques demonstrated are intended for:
- Security professionals conducting authorized assessments
- Defensive security teams understanding attack methodologies
- Educational purposes in controlled environments

Unauthorized testing of systems is strictly prohibited and may violate:
- Computer Fraud and Abuse Act (CFAA)
- Various international computer misuse laws
- Organizational security policies

## Technical Documentation Standards
All write-ups adhere to the following documentation standards:
1. **Reproducibility**: Commands and techniques are documented with sufficient detail for replication
2. **Accuracy**: Findings are validated through multiple verification methods
3. **Context**: Technical details are accompanied by explanatory context for understanding
4. **Remediation Focus**: Vulnerabilities are documented with corresponding mitigation strategies
*This portfolio represents practical application of offensive security techniques in controlled training environments. The skills demonstrated translate directly to professional penetration testing engagements while maintaining strict adherence to ethical guidelines and legal boundaries.*
