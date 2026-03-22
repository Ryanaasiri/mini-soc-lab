# Mini SOC Lab

This project demonstrates a basic Security Operations Center (SOC) lab focused on endpoint detection and investigation using real telemetry. The goal is to simulate attacker behavior and analyze it across multiple data sources to understand how attacks can be detected and correlated.

---

## Overview

A controlled lab environment was built using:

- **Windows** as the victim machine  
- **Kali Linux** as the attacker machine  

Both systems were connected within an isolated network to simulate internal attack scenarios.

The following tools were used to collect and analyze telemetry:

- **Sysmon** — endpoint activity logging  
- **Splunk** — log analysis and detection  
- **Wireshark** — packet capture and traffic inspection  
- **Snort** — network intrusion detection system  

---

## Objectives

- Understand how attacker activity appears in endpoint logs  
- Detect suspicious PowerShell behavior using Sysmon and Splunk  
- Analyze network communication between victim and attacker  
- Correlate events across endpoint and network telemetry  
- Reconstruct a full attack chain from execution to persistence  

---

## Scenarios

### Scenario 1 — PowerShell Attack Chain

This scenario simulates a simple but realistic attack chain using PowerShell:

- PowerShell execution with bypass techniques  
- Remote payload retrieval from an attacker-controlled host  
- Outbound HTTP communication  
- Registry-based persistence  

The objective is to observe how each stage is reflected in logs and network traffic.

Scenario details:  
- `scenarios/`

Investigation and analysis:  
- `investigations/`

---

## Data Sources

The following Sysmon events were used during analysis:

- **Event ID 1** — Process creation (execution)  
- **Event ID 3** — Network connections  
- **Event ID 13** — Registry modifications (persistence)  

These events provide visibility into attacker activity at the endpoint level.

---

## Detection Approach

Detection was performed using:

- Splunk queries to identify suspicious PowerShell execution and network activity  
- Snort rules to detect network-level behavior  
- Packet analysis using Wireshark to validate traffic  

Focus was placed on identifying abnormal behavior rather than known signatures.

---


---

## Key Concepts Demonstrated

- Endpoint telemetry analysis using Sysmon  
- Detection of suspicious PowerShell activity  
- Network traffic inspection and validation  
- Event correlation across multiple data sources  
- Attack chain reconstruction  

---

## Notes

This project focuses on detection and investigation rather than complex exploitation techniques. The attack scenario is intentionally simple to emphasize analysis, correlation, and understanding of system behavior.
