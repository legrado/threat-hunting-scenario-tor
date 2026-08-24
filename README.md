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

Searched for any file that had the string "tor" in it and discovered that the user "ligrado" downloaded a TOR installer, followed by the creation of multiple TOR-related files on the desktop. These included `tor.exe`, TOR Browser shortcuts, browser storage files, and other TOR-related files. These events began at `2026-08-12T17:58:11.0237467Z`.

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
<img width="1108" height="422" alt="image" src="https://github.com/user-attachments/assets/cee06f97-1a88-419f-b10e-d33884f2a201" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.19.exe". Based on the logs returned, the user "ligrado" on the "aiden-threat-hu" device ran the file `tor-browser-windows-x86_64-portable-15.0.19.exe` from their Downloads folder. Multiple `ProcessCreated` events associated with the installer were recorded.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "aiden-threat-hu"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.19.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1129" height="322" alt="image" src="https://github.com/user-attachments/assets/457c15d3-45f7-41da-9e7b-cc203953f7ac" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "ligrado" actually opened the TOR browser. There was evidence that the TOR Browser Firefox process was launched at approximately `1:07:29 PM`. Several additional instances of `firefox.exe` as well as `tor.exe` were spawned afterwards, indicating an active TOR Browser session.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "aiden-threat-hu"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```
<img width="1091" height="416" alt="image" src="https://github.com/user-attachments/assets/016c80ce-b951-42db-916a-f478b75d9a93" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish connections using known TOR ports. The results showed `tor.exe` successfully connecting to the remote IP address `157.180.78.167` on port `9001`. Two successful connections to this address were observed. The results also showed `firefox.exe` successfully connecting to the local TOR SOCKS proxy at `127.0.0.1:9150`.

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
<img width="1146" height="231" alt="image" src="https://github.com/user-attachments/assets/90a77122-13cb-4c25-8735-3f09e0777399" />


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
- **Action:** Multiple process creation events associated with the TOR Browser installer were detected.
- **File Path:** `C:\Users\ligrado\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

### 3. TOR Browser Files Extracted

- **Timestamp:** Approximately `12:58:42 PM`
- **Event:** Multiple TOR-related files were created under the user's Desktop following execution of the installer. These included the primary `tor.exe` executable and other TOR Browser-related files and shortcuts.
- **Action:** TOR Browser file creation detected.
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Process Execution - TOR Browser Launch

- **Timestamp:** `1:07:29 PM`
- **Event:** User "ligrado" opened the TOR browser. Subsequent processes associated with TOR Browser, including multiple `firefox.exe` processes and `tor.exe`, were created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR Browser-related executables detected.
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\firefox.exe`

### 5. TOR Service Process Started

- **Timestamp:** `1:07:44 PM`
- **Event:** The TOR networking component `tor.exe` was launched from the TOR Browser directory. The process configured the local TOR SOCKS service on `127.0.0.1:9150` and the control port on `127.0.0.1:9151`.
- **Action:** TOR service process creation detected.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 6. TOR Browser Connected to Local SOCKS Proxy

- **Timestamp:** `1:08:09 PM`
- **Event:** `firefox.exe` established a successful connection to `127.0.0.1` on port `9150`. This corresponds to the local SOCKS proxy configured by `tor.exe` and links the TOR Browser Firefox process to the TOR networking service.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **Connection:** `127.0.0.1:9150`

### 7. Network Connection - TOR Network

- **Timestamp:** `1:11:54 PM`
- **Event:** `tor.exe` successfully established a connection to the remote IP address `157.180.78.167` on port `9001`. This provides network evidence consistent with active TOR communication.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **Remote Connection:** `157.180.78.167:9001`
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 8. Additional TOR Network Connection

- **Timestamp:** `1:13:12 PM`
- **Event:** `tor.exe` established another successful connection to `157.180.78.167` on port `9001`, providing additional evidence of ongoing TOR network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **Remote Connection:** `157.180.78.167:9001`

### 9. TOR Browser Launched Again

- **Timestamp:** Approximately `1:23:06 PM`
- **Event:** New `firefox.exe` processes were created from the TOR Browser directory, indicating that TOR Browser was launched or restarted.
- **Action:** TOR Browser process creation detected.
- **File Path:** `C:\Users\ligrado\Desktop\Tor Browser\Browser\firefox.exe`

### 10. TOR Service Started Again

- **Timestamp:** Approximately `1:23:07 PM`
- **Event:** A new `tor.exe` process was created from the TOR Browser directory. The process again configured `127.0.0.1:9150` as its SOCKS port and `127.0.0.1:9151` as its control port.
- **Action:** TOR service process creation detected.
- **Process:** `tor.exe`

---

## Summary

The user "ligrado" on the "aiden-threat-hu" device installed and used the TOR Browser on August 12, 2026. The TOR Browser portable installer was executed from the user's Downloads folder, after which multiple TOR-related files were created on the Desktop.

At approximately `1:07 PM`, TOR Browser processes including `firefox.exe` and the TOR networking component `tor.exe` were launched. Network telemetry confirmed that `firefox.exe` connected to TOR's local SOCKS proxy at `127.0.0.1:9150`.

The `tor.exe` process successfully established connections to `157.180.78.167` over port `9001`. Two successful port `9001` connections were observed, providing evidence consistent with active TOR network communication.

TOR Browser was launched again at approximately `1:23 PM`, followed by another TOR service process and additional TOR Browser activity. Overall, the evidence confirms that TOR Browser was installed, executed, and actively used for TOR network connectivity on the device.

---

## Response Taken

TOR usage was confirmed on the endpoint `aiden-threat-hu` by the user `ligrado`. The device was isolated, and the user's direct manager was notified.

---
