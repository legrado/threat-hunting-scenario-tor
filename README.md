<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/legrado/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "ligrado" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at `2026-08-12T17:58:11.0237467Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "aiden-threat-hu"
| where InitiatingProcessAccountName == "ligrado"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-08-12T17:58:11.0237467Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.19.exe". Based on the logs returned, an employee on the "aiden-threat-hu" device ran the file `tor-browser-windows-x86_64-portable-15.0.19.exe` from their Downloads folder.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "aiden-threat-hu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.19.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "ligrado" actually opened the TOR browser. There was evidence that the TOR Browser Firefox process was launched at approximately `1:07:29 PM`. Several additional instances of `firefox.exe` as well as `tor.exe` were spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "aiden-threat-hu"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `1:11:54 PM`, the user "ligrado" on the "aiden-threat-hu" device successfully established a connection to the remote IP address `157.180.78.167` on port `9001`. The connection was initiated by the process `tor.exe`. There were also other TOR-related connections over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "aiden-threat-hu"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline

### 1. File Download - TOR Installer

- **Timestamp:** `2026-08-12T17:58:11.0237467Z`
- **Event:** The TOR Browser portable installer `tor-browser-windows-x86_64-portable-15.0.19.exe` was identified in user "ligrado's" Downloads folder.
- **Action:** File activity detected.
- **File Path:** `C:\Users\ligrado\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** Approximately `12:58:24–12:58:25 PM`
- **Event:** The user "ligrado" executed the file `tor-browser-windows-x86_64-portable-15.0.19.exe`, initiating the TOR Browser installation/extraction.
- **Action:** Process creation detected.
- **File Path:** `C:\Users\ligrado\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `1:07:29 PM`
- **Event:** User "ligrado" opened the TOR browser. Subsequent processes associated with TOR Browser, including `firefox.exe` and `tor.exe`, were created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `1:11:54 PM`
- **Event:** A network connection to IP `157.180.78.167` on port `9001` was established using `tor.exe`, confirming TOR network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Events:**
  - `tor.exe` connected to `167.114.103.133` on port `443`.
  - `tor.exe` connected to `109.70.100.248` on port `443`.
  - `firefox.exe` connected to the local TOR SOCKS proxy `127.0.0.1` on port `9150`.
  - `tor.exe` connected to `192.42.116.165` on port `443`.
  - `tor.exe` connected to `157.180.78.167` on port `9001`.
- **Event:** Multiple TOR network connections were established, indicating ongoing TOR Browser activity.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Event:** The user "ligrado" created a file named `tor-shopping-list.txt` on the desktop.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ligrado\Desktop\tor-shopping-list.txt`

---

## Summary

The user "ligrado" on the "aiden-threat-hu" device installed and used the TOR Browser on August 12, 2026. The TOR installer was executed from the user's Downloads folder and extracted TOR Browser files to the Desktop. TOR Browser and `tor.exe` were subsequently launched, and network telemetry confirmed that the browser connected to TOR's local SOCKS proxy on `127.0.0.1:9150`. The `tor.exe` process also established multiple successful external connections, including connections to `157.180.78.167` over port `9001`, consistent with TOR network activity.

TOR Browser was launched again around 1:23 PM, followed by additional TOR-related connections. Overall, the evidence confirms that TOR Browser was installed, executed, and actively used for TOR network connectivity on the device.

---

## Response Taken

TOR usage was confirmed on the endpoint `aiden-threat-hu` by the user `ligrado`. The device was isolated, and the user's direct manager was notified.

---
