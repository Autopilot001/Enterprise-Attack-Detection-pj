# Enterprise Attack Detection Lab


A home-lab SOC project for practicing detection engineering across cloud identity and network activity. The lab combines Microsoft Entra ID, Splunk Enterprise, Kali Linux, and an Ubuntu victim VM on an isolated host-only network.


## Lab architecture


**Microsoft Entra ID:** Developer tenant providing sign-in and audit events, Conditional Access, and Identity Protection telemetry.
**Splunk Enterprise:** SIEM for cloud identity and host logs.
**Kali Linux:** Generates controlled reconnaissance and SSH password-guessing activity.
**Ubuntu victim VM:** Runs SSH and a web service, with logs sent through a Splunk Universal Forwarder.
**Network:** Host-only subnet `192.168.56.0/24`, isolated from the home LAN.


Entra ID events are collected with the Splunk Add-on for Microsoft Cloud Services and an Azure App Registration with `AuditLog.Read.All` and `Reports.Read.All` permissions. The victim forwards `auth.log`, `ufw.log`, and `syslog` to Splunk on port `9997`.


## Identity telemetry


The Entra ID tenant uses Conditional Access policies to block legacy authentication and require MFA. Identity Protection sign-in risk and user risk policies provide additional signals.


Test sign-ins, failed logins, and varied source IPs generate lab events for analysis. Detections use fields such as `riskLevelDuringSignIn`, `conditionalAccessStatus`, and `status.errorCode`.


## Network simulations


All activity is limited to the lab victim on the host-only network.


Nmap reconnaissance includes host discovery, SYN and full-port scans, service detection, and a small UDP scan:


```bash
nmap -sn 192.168.56.0/24
sudo nmap -sS -T4 192.168.56.20
sudo nmap -sS -p- -T4 192.168.56.20
nmap -sV -p22,80,443 192.168.56.20
sudo nmap -sU --top-ports 50 192.168.56.20
```


Hydra generates failed SSH login events using a throwaway lab account:


```bash
hydra -l labtest -P rockyou-sample.txt ssh://192.168.56.20 -t 4
```


The simulations map to MITRE ATT&CK techniques T1046 for network service discovery, T1110.001 for password guessing, and T1592 for service enumeration.


## Splunk detections


Five custom SPL detections analyze the generated telemetry:


- **Port scanning — T1046:** Flags a source touching at least 15 destination ports within 60 seconds. Severity increases at 50 and 100 ports.
- **SSH brute force — T1110.001:** Detects at least five failed logins for the same user and source within five minutes. A companion search flags a brute-force attempt followed by a successful login.
- **Entra ID impossible travel — T1078.004:** Identifies a user signing in from geographically distant IPs within an implausibly short interval, using `iplocation` and `streamstats`.
- **Risky Entra ID sign-in — T1110 / T1078:** Alerts on high-risk sign-ins or repeated Conditional Access denials in ten-minute windows.
- **Correlated reconnaissance and brute force:** Joins scan and login activity from the same source within 30 minutes to highlight a higher-confidence sequence.


## Dashboard and response


The `soc_overview_dashboard.xml` dashboard summarizes scan volume, top brute-force sources, Entra ID sign-in risk, and fired alerts. The project also documents triage and containment steps for the telemetry it generates.

