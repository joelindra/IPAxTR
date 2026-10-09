# IPAxTR — iPhone Application Extractor, FairPlay Decryptor & Binary Inspector

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform: iOS 14-16+](https://img.shields.io/badge/iOS-14.0--16.7%2B-lightgrey.svg)](https://apple.com)
[![License: Educational / Research](https://img.shields.io/badge/License-Security%20Research-red.svg)](#-legal--ethical-scope)
[![Analysis: Ghidra & IDA Pro](https://img.shields.io/badge/Decompiler-Ghidra%20%7C%20IDA%20Pro-green.svg)](https://ghidra-sre.org/)

An interactive CLI and automated binary pipeline engineered from scratch in pure Python for **iOS penetration testing, mobile security research, application backup, and binary preparation for reverse engineering (Ghidra / IDA Pro)**.

---

## 📑 Table of Contents
1. [Core Features](#-core-features)
2. [Architecture & Low-Level Design (LLD)](#-architecture--low-level-design-lld)
3. [Prerequisites & Environment Setup](#-prerequisites--environment-setup)
4. [Comprehensive Guide: Interactive TUI Suite (`main.py`)](#-comprehensive-guide-interactive-tui-suite-mainpy)
   - [Startup & Automatic Self-Check](#1-startup--automatic-self-check)
   - [Application Browser & Navigation Bar](#2-application-browser--navigation-bar)
   - [Detailed Walkthrough of Application Actions (1, 2, 3, 4)](#3-detailed-walkthrough-of-application-actions-1-2-3-4)
   - [Stand-Alone Unpack Tool (`[U]`)](#4-stand-alone-unpack-tool-u)
5. [End-to-End Reverse Engineering with Ghidra & IDA Pro](#-end-to-end-reverse-engineering-with-ghidra--ida-pro)
6. [Manual CLI Command Reference (`python -m ipaxtr`)](#-manual-cli-command-reference-python--m-ipaxtr)
7. [Technical Deep-Dive: FairPlay DRM on Modern iOS (iOS 16+)](#-technical-deep-dive-fairplay-drm-on-modern-ios-ios-16)
8. [App Extension Handling Strategy (`.appex`)](#-app-extension-handling-strategy-appex)
9. [Project File Structure](#-project-file-structure)
10. [Troubleshooting Guide](#-troubleshooting-guide)
11. [Legal & Ethical Scope](#-legal--ethical-scope)

---

## 🚀 Core Features

- **Direct USB Communication (`usbmuxd`):** Talks directly to connected iOS devices over USB on Windows, macOS, and Linux without requiring network pairing or SSH for basic operations.
- **Jailbreak Environment Detection:** Automatically inspects the runtime environment, verifying root privileges (`UID 0`) via the Frida bridge and probing Dopamine Rootless markers (`/var/jb`).
- **High-Throughput Bundle Pulling:** Transmits complete `.app` bundle directories over a dedicated Frida root agent (~14 MB/s sustained USB transfer).
- **Windows Symlink & Permission Preservation:** Preserves POSIX symbolic links and executable file mode bits (`0o755`) using a JSON sidecar metadata system (`.__ipaxtr_meta__.json`) to eliminate Windows filesystem corruption.
- **FairPlay Runtime Memory Decryption:** Page-diffs the binary's `__TEXT` file segment against decrypted memory pages faulted into RAM, reliably bypassing the lazy decryption model introduced in modern iOS versions (iOS 16+).
- **Intelligent Extension Resolution:** Automatically isolates background plugins (`PlugIns/*.appex`) and provides configurable handling strategies (`strip`, `patch`, `keep`).
- **Seamless Ghidra / IDA Pro Export:** Bypasses ZIP container issues by stripping the `.ipa` envelope, verifying Mach-O plaintext headers (`cryptid=0`), exporting to `binaries/<AppName>/<Binary>`, and launching Windows File Explorer with the binary highlighted.

---

## 📐 Architecture & Low-Level Design (LLD)

### End-to-End Pipeline Flowchart

```mermaid
flowchart TD
    subgraph S1["1. PRE-FLIGHT & DEVICE DISCOVERY"]
        USB["Connected iPhone (USB)"] --> MUX["usbmuxd Driver Interface"]
        MUX --> DEV_QUERY["Query Lockdown Service Registry"]
        DEV_QUERY --> JB_PROBE{"Probe Jailbreak State<br/>(Frida root UID 0 & /var/jb)"}
        JB_PROBE -->|Verified| JB_READY["Jailbreak Status: READY"]
        JB_PROBE -->|Failed| JB_NOT_READY["Jailbreak Status: NOT READY<br/>(Limited to App Data Sandbox)"]
    end

    subgraph S2["2. APPLICATION INDEXING & INTERACTION"]
        JB_READY --> PROXY["Query MobileInstallation Proxy"]
        PROXY --> CATEGORIZE["Classification Engine<br/>(User / Apple Removable / Jailbreak / System)"]
        CATEGORIZE --> MAIN_UI["Interactive TUI Engine (main.py)"]
        MAIN_UI --> ACTION_SELECT{"Select Action Menu"}
    end

    subgraph S3["3. BUNDLE EXTRACTION PIPELINE"]
        ACTION_SELECT -->|"Action [1]: Standard IPA"| PULL_BRIDGE["Recursive Pull via Frida Root Bridge"]
        PULL_BRIDGE --> SIDECAR["Generate POSIX Metadata Sidecar<br/>(Symlinks, UNIX permissions, 0o755 exec bits)"]
        SIDECAR --> LOCAL_STAGING["Local Staging Directory: work/AppName.app"]
    end

    subgraph S4["4. FAIRPLAY RUNTIME DECRYPTION ENGINE (decrypt.py)"]
        ACTION_SELECT -->|"Action [2]: Decrypt IPA / Action [3]: Ghidra Prep"| CHECK_STAGING{"Bundle Staged in work/?"}
        CHECK_STAGING -->|No| PULL_BRIDGE
        CHECK_STAGING -->|Yes| SCAN_MACHOS["Scan Mach-O Binaries<br/>(Main Binary, Frameworks, Extensions)"]
        SCAN_MACHOS --> SPAWN["Spawn Target App via Frida Engine"]
        SPAWN --> KERNEL_PAGING["iOS Kernel Faults Decrypted Pages into RAM"]
        KERNEL_PAGING --> PAGE_DIFF["Diff Memory __TEXT Segments vs Disk<br/>(Overwrite differing encrypted pages on disk)"]
        PAGE_DIFF --> EXT_CHECK{"Unloaded Extensions<br/>in PlugIns/*.appex?"}
        EXT_CHECK -->|Strip (Recommended)| STRIP_APPEX["Prune .appex (Clean Sideloading)"]
        EXT_CHECK -->|Patch| PATCH_APPEX["Patch cryptid=0 on .appex disk headers"]
        EXT_CHECK -->|Keep| KEEP_APPEX["Retain original encrypted .appex"]
        STRIP_APPEX --> PATCH_CRYPTID["Patch Mach-O LC_ENCRYPTION_INFO_64 Header<br/>cryptid = 0"]
        PATCH_APPEX --> PATCH_CRYPTID
        KEEP_APPEX --> PATCH_CRYPTID
    end

    subgraph S5["5. PACKAGING & ARTIFACT EXPORT"]
        PATCH_CRYPTID --> TARGET_FORMAT{"Target Deliverable"}
        TARGET_FORMAT -->|"Package .ipa"| REPACK["packaging.py:<br/>Reconstruct Zip Payload/AppName.app<br/>Replay symlinks & 0o755 permissions"]
        REPACK --> OUT_IPA["Generated Archive: ipas/AppName.ipa"]
        
        TARGET_FORMAT -->|"Decompiler Binary"| EXPORT_RAW["main.py export_and_guide_ghidra():<br/>Extract Mach-O Executable from Bundle"]
        EXPORT_RAW --> VERIFY_HEADER["Verify Mach-O Headers (64-bit arm64, cryptid=0)"]
        VERIFY_HEADER --> OUT_BIN["Exported Binary: binaries/AppName/Executable"]
        OUT_BIN --> AUTO_EXPLORER["Auto-Launch Windows Explorer (/select)"]
    end

    subgraph S6["6. STATIC REVERSE ENGINEERING (GHIDRA / IDA PRO)"]
        OUT_BIN -.->|Drag & Drop Mach-O| GHIDRA_IMPORT["Ghidra Project Import"]
        GHIDRA_IMPORT --> IMPORT_SETTINGS["Format: Mac OS X Mach-O<br/>Language: AARCH64:LE:64:v8A (Apple)"]
        IMPORT_SETTINGS --> AUTO_ANALYSIS["Run Auto Analysis & Demangler Swift"]
        AUTO_ANALYSIS --> DECOMPILED_CODE["Reconstructed C / Swift Pseudocode"]
    end

    classDef primary fill:#1e293b,stroke:#06b6d4,stroke-width:2px,color:#fff;
    classDef success fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef warning fill:#78350f,stroke:#f59e0b,stroke-width:2px,color:#fff;
    class S1,S2,S3,S4,S5,S6 primary;
    class OUT_IPA,OUT_BIN,DECOMPILED_CODE success;
    class JB_NOT_READY,EXT_CHECK warning;
```

---

## 💻 Prerequisites & Environment Setup

### 1. Host Machine Requirements
- **Operating System:** Windows 10/11, macOS, or Linux.
- **Python Version:** Python 3.9 or higher.
- **USB Mobile Drivers (Windows):** Install **Apple Devices** (available via Microsoft Store) or **iTunes** to ensure `usbmuxd` background services are installed and active.

### 2. iOS Device Requirements
- **Jailbreak:** Jailbroken device (e.g., Dopamine on iOS 15.0 – 16.7+).
- **Frida Server:** Install the official **Frida** package from Sileo / Zebra. Ensure the `frida-server` daemon executes as root (`UID 0`).
- **USB Link:** Connect the iPhone using a data-capable USB cable (not charge-only), unlock the screen, and tap **"Trust This Computer"**.

### 3. Repository Installation

```powershell
# Navigate to the project root
cd E:\HACKING\IPAxTR

# Create and activate a Python virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate

# Install required Python dependencies
pip install -r requirements.txt
```

Verify your device connection and status:
```powershell
python -m ipaxtr devices
python -m ipaxtr info
```

---

## 🖥 Comprehensive Guide: Interactive TUI Suite (`main.py`)

The primary entry point of IPAxTR is `main.py`, which provides a terminal interface built with Rich.

Launch the suite:
```powershell
python main.py
```

### 1. Startup & Automatic Self-Check

Upon launch, the program performs an automated environment check:
- **Prerequisites Table:** Confirms presence of Python libraries (`usbmuxd`, `frida`, `rich`, etc.) and detects USB hardware.
- **Jailbreak Status Badge:** Displays `[READY]` if Frida runs as root (`UID 0`) with Dopamine markers present, or `[NOT READY]` if restricted.
- **Target Device Information Panel:** Shows Device Name, Model, OS Version, UDID, and USB Connection ID.

---

### 2. Application Browser & Navigation Bar

The suite fetches the application database from the device and displays it in an interactive table:

| Column | Description |
|---|---|
| **#** | Application index number used for selection. |
| **Name** | Display name of the application. |
| **Bundle ID** | Unique CFBundleIdentifier (e.g., `telkomsel.mytelkomsel-dev`). |
| **Version** | Short version and build number. |
| **Type** | Category badge: `[User]`, `[Apple]`, or `[Jailbreak]`. |
| **Size** | Disk footprint of the application bundle. |
| **Status** | Encryption status (`Plaintext` vs `Encrypted (cryptid=1)`). |

#### Navigation Bar Commands:
- **`[1-N]` (Number):** Select an application to open its Actions Menu.
- **`[U]` (Unpack for Ghidra):** Launch the stand-alone IPA unpacker and Mach-O binary extractor.
- **`[C]` (Category):** Filter displayed applications:
  1. Visible Screen Applications (User + Apple Removable + Jailbreak) — *Default*
  2. Third-Party User Applications (App Store / TestFlight)
  3. Apple Removable Applications (Stock apps like Calculator, Notes, Files)
  4. Jailbreak Applications (Sileo, Zebra, TrollStore)
  5. All System Daemons & Components (Complete device index of 170+ entries)
- **`[S]` (Search):** Filter applications by name or Bundle ID keyword.
- **`[X]` (Clear Filter):** Reset search filter and return to category view.
- **`[R]` (Refresh):** Re-query the device's installation proxy.
- **`[Q]` (Quit):** Gracefully terminate the session.

---

### 3. Detailed Walkthrough of Application Actions (1, 2, 3, 4)

Selecting an application opens the **Available Actions** menu:

```text
[1] Standard IPA Extract       (Pull bundle -> Package into .ipa in ipas/) [DEFAULT]
[2] Extract & Decrypt .ipa     (FairPlay runtime decryption -> .ipa package)
[3] Prepare for Ghidra / IDA   (Export decrypted Mach-O executable for decompiler)
[4] Inspect Encryption Header  (Check Mach-O cryptid flag directly on device)
[B] Back to Applications List
```

---

#### Action `[1]` — Standard IPA Extract
- **Purpose:** Extracts the application bundle directly from the device and packages it into a standard `.ipa` file inside `ipas/`.
- **When to Use:**
  - Creating a backup of jailbreak tweaks, sideloaded applications, or development builds.
  - Extracting plaintext applications that have no FairPlay DRM.
- **Workflow:**
  1. Pulls the `.app` bundle from `/private/var/containers/Bundle/Application/...` to `work/<App>.app`.
  2. Preserves symlinks and UNIX permissions in `work/<App>.app/.__ipaxtr_meta__.json`.
  3. Archives the bundle into `ipas/<App>.ipa` with standard `Payload/<App>.app/` structure.

---

#### Action `[2]` — Extract & Decrypt .ipa
- **Purpose:** Performs end-to-end FairPlay DRM decryption via runtime memory dumping and generates an installable, decrypted `.ipa` file.
- **When to Use:**
  - Creating installable `.ipa` packages for sideloading via TrollStore, Sideloadly, or AltStore.
  - Analyzing third-party App Store or TestFlight binaries.
- **Workflow:**
  1. Prompts for legal authorization confirmation.
  2. Reuses existing local staging in `work/<App>.app` if already pulled, or performs a fresh pull.
  3. Scans all Mach-O binaries in the bundle (main executable, dynamic frameworks, and background plugins).
  4. If App Extensions (`PlugIns/*.appex`) are detected, prompts for handling strategy:
     - `[1] Strip` (*Default & Recommended*): Prunes un-decrypted extensions so sideloading succeeds without entitlement errors.
     - `[2] Patch`: Sets `cryptid=0` on extension headers on disk.
     - `[3] Keep`: Retains original encrypted extensions.
  5. Spawns the application on-device via Frida, attaches to the process, and dumps decrypted memory pages.
  6. Page-diffs the binary against RAM, patches disk bytes, and modifies the header to `cryptid=0`.
  7. Packages the decrypted bundle into `ipas/<App>.ipa`.

---

#### Action `[3]` — Prepare for Ghidra / IDA Pro *(Recommended for Reverse Engineering)*
- **Purpose:** Prepares a clean, decrypted Mach-O executable file ready for import into Ghidra, IDA Pro, or Binary Ninja.
- **When to Use:**
  - You want to decompile the application and analyze its C, Objective-C, or Swift code.
  - Avoids the common beginner mistake of dragging an `.ipa` (ZIP archive) into Ghidra.
- **Workflow:**
  1. Inspects local staging in `work/<App>.app` (pulls from device if not present).
  2. Verifies whether the main binary is encrypted. If `cryptid=1`, automatically offers to run FairPlay runtime decryption first.
  3. Extracts the true Mach-O binary from the bundle and copies it to:
     ```text
     E:\HACKING\IPAxTR\binaries\<AppName>\<ExecutableName>
     ```
  4. Displays a **Ghidra / IDA Pro Reverse Engineering Guide** panel with verified binary size, 64-bit arm64 architecture, and exact import settings.
  5. Prompts: `Open folder in Windows File Explorer now? [Y/n]`. Selecting `Y` opens Windows Explorer with the binary highlighted.

---

#### Action `[4]` — Inspect Encryption Header
- **Purpose:** Rapid remote inspection of the application's Mach-O header without downloading the entire bundle.
- **When to Use:**
  - Verifying if an app is protected by FairPlay DRM before committing to a full download.
- **Workflow:**
  - Reads the first megabyte of the executable directly over the Frida root bridge, parses `LC_ENCRYPTION_INFO_64`, and prints `cryptid`, `cryptoff`, `cryptsize`, and target architecture.

---

### 4. Stand-Alone Unpack Tool (`[U]`)

Typing `U` in the main menu opens the `.ipa` Unpacker Tool:
- Scans `ipas/` for previously generated `.ipa` files.
- Allows selecting an existing `.ipa` or entering a custom path.
- Extracts the Mach-O executable, verifies its encryption status, places it in `binaries/`, and launches Windows Explorer ready for Ghidra.

---

## 🔍 End-to-End Reverse Engineering with Ghidra & IDA Pro

> ⚠️ **CRITICAL WARNING:**  
> **DO NOT** drag-and-drop an `.ipa` file into Ghidra!  
> An `.ipa` is a compressed ZIP container. Importing it causes Ghidra to misidentify the ZIP bytes as raw microcontroller firmware (misclassified as ARM Cortex-M with vector tables like `SysTick`), resulting in `halt_baddata` errors and invalid assembly.

Always import the extracted Mach-O binary from:
```text
E:\HACKING\IPAxTR\binaries\<AppName>\<ExecutableName>
```

### Step-by-Step Ghidra Import Guide

1. **Launch Ghidra** and open or create a project (`File` ➔ `New Project` ➔ `Non-Shared Project`).
2. **Drag & Drop** the binary from `binaries/<AppName>/<ExecutableName>` into your Ghidra project window.
3. In the Import Dialog, confirm the detected parameters:
   - **Format:** `Mac OS X Mach-O`
   - **Language:** `AARCH64:LE:64:v8A (Apple)` *(or `ARM:v8:64`)*
   - **Compiler:** `default`
4. Click **OK**, then double-click the imported binary to launch **CodeBrowser**.
5. When prompted with *"has not been analyzed. Would you like to analyze it now?"*, select **Yes**.
6. In the Analysis Options dialog:
   - Ensure **Demangler Swift** and **Objective-C** analyzers are checked (this demangles mangled Swift symbols like `_$s14...` into readable function signatures).
   - Click **Analyze**. (For large binaries ~400 MB, analysis may take several minutes; monitor the progress bar in the bottom-right corner).
7. Open the Decompiler window: **Window** ➔ **Decompiler** (or press the `C` toolbar icon).

### Navigating Decompiled Code

- **Locating Main Application Logic:**  
  In the **Symbol Tree** panel (left), expand **Functions** or **Classes**. Filter by keywords such as `AppDelegate`, `ViewController`, `Login`, `Auth`, or `Network`. Click any function to view its decompiled C / Swift pseudocode in the Decompiler panel.
- **Finding Hardcoded Secrets, URLs & API Endpoints:**  
  Go to **Search** ➔ **Program Text** (or **Window** ➔ **Defined Strings**). Enter target strings (e.g., `/api/v1/`, `token`, `secret`). Double-click any string and press **`X`** (Cross-Reference / XREF) to find all functions that access it.
- **Analyzing Dynamic Frameworks:**  
  If a function in `Imports` points to `@rpath/CustomFramework.framework`, open the framework binary directly from:
  ```text
  E:\HACKING\IPAxTR\work\<AppName>.app\Frameworks\<CustomFramework>.framework\<CustomFramework>
  ```

---

## ⌨️ Manual CLI Command Reference (`python -m ipaxtr`)

All capabilities can also be executed via direct command-line arguments:

```powershell
# 1. Device Discovery
python -m ipaxtr devices
python -m ipaxtr info [UDID]

# 2. Installed Application Listing
python -m ipaxtr apps -v
python -m ipaxtr apps --type User
python -m ipaxtr apps --type Jailbreak

# 3. Remote Encryption Header Inspection
python -m ipaxtr check com.example.app --device --frida

# 4. Pull Application Bundle (Without Packaging)
python -m ipaxtr pull com.example.app --method frida --out-dir work/Example.app

# 5. Extract & Package into .ipa
python -m ipaxtr extract com.example.app --method frida -o ipas/

# 6. FairPlay Runtime Memory Decryption
python -m ipaxtr decrypt com.example.app --app-dir work/Example.app --extensions strip --i-own-this-build

# 7. Unpack an Existing .ipa
python -m ipaxtr unpack ipas/Example.ipa -o work/unpacked/

# 8. Repackage a Staged .app Bundle into an .ipa
python -m ipaxtr pack work/Example.app -o ipas/Rebuilt.ipa
```

---

## 🔬 Technical Deep-Dive: FairPlay DRM on Modern iOS (iOS 16+)

### 1. Mach-O Encryption Header (`LC_ENCRYPTION_INFO_64`)
64-bit ARM Mach-O binaries contain load command `0x2C` (`LC_ENCRYPTION_INFO_64`):
- `cryptoff`: Byte offset where the encrypted binary block begins.
- `cryptsize`: Nominal length of the encrypted code segment.
- `cryptid`: Encryption flag (`1` = FairPlay encrypted, `0` = Plaintext).

### 2. The iOS 16+ "Lazy Decryption" Problem
On iOS 16 and later, the kernel implements lazy demand-paging for FairPlay binaries:
- The kernel does not decrypt the entire binary into memory at initial spawn. Pages are decrypted on demand when execution hits a memory page fault.
- As a result, `cryptsize` in the disk header often lists only `0x1000` (4 KB / a single memory page), even on 400+ MB binaries.
- Tools that blindly trust `cryptsize` fail to dump the full binary.
- **IPAxTR's Solution:** IPAxTR reads the entire `__TEXT` segment, compares each 4 KB memory page (`0x1000`) between the Frida process memory image and the disk file (*page-diffing*), and overwrites only differing pages before patching `cryptid=0`.

---

## 🧩 App Extension Handling Strategy (`.appex`)

Modern iOS applications (e.g., banking apps, messengers) bundle multiple extensions in `PlugIns/*.appex` (WidgetKit, Notification Services, Share Extensions).

### The Technical Challenge:
App Extensions run inside **independent system daemon processes** managed by iOS subsystems (`pkd`). They are never loaded into the main application process address space during standard launch.

### IPAxTR Solution via `--extensions {strip,patch,keep}`:
1. **`strip` (Default & Recommended):** Removes un-decrypted `.appex` directories from the final bundle. The resulting `.ipa` installs cleanly via TrollStore, Sideloadly, or AltStore without entitlement or FairPlay verification failures.
2. **`patch`:** Preserves extension files and patches `cryptid=0` on their disk headers.
3. **`keep`:** Keeps original encrypted extension binaries unmodified.

---

## 📂 Project File Structure

```text
IPAxTR/
├── .gitignore             # Git ignore rules for build, staging, and output files
├── main.py                # Interactive TUI Suite & Ghidra/IDA preparation tool
├── requirements.txt       # Python dependencies (frida, rich, usbmuxd, etc.)
├── README.md              # Technical documentation and Low-Level Design
├── ipaxtr/                # Core library modules
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Argparse command dispatcher
│   ├── decrypt.py         # Runtime page-diffing memory dump engine
│   ├── device.py          # usbmuxd, lockdown, and installation proxy transport
│   ├── frida_bridge.py    # Root filesystem agent and bundle puller
│   ├── ipa.py             # IPA inspection, Info.plist parser, and unpacker
│   ├── macho.py           # Mach-O header parser (load commands, crypt info)
│   ├── packaging.py       # ZIP packager with symlink & permission replay
│   └── util.py            # Utility helpers, Rich formatting, and plist decoder
├── tests/
│   └── test_offline.py    # Offline unit test suite (runs without device)
├── work/                  # [Staging] Local bundle directories (.app)
├── ipas/                  # [Output] Packaged .ipa archives
└── binaries/              # [Output] Exported Mach-O binaries for Ghidra/IDA
```

---

## ❓ Troubleshooting Guide

| Issue / Symptom | Root Cause | Resolution |
|---|---|---|
| `no iPhone detected` | Cable lacks data lines, device locked, or driver missing | Use an original data cable, unlock device, tap **Trust This Computer**, and install Apple Devices / iTunes. |
| `frida: not running as root` | `frida-server` running in a restricted sandbox | Install Frida via Sileo/Zebra from the official repository under Dopamine/rootless. |
| `halt_baddata` / Bad Instructions in Ghidra | Imported `.ipa` (ZIP file) instead of Mach-O binary | Use Action **`[3]`** in `main.py` to export the true Mach-O binary to `binaries/`, then import that file. |
| `module not loaded in app process` | App Extension (`.appex`) runs in a separate process | Select Option **`[1] Strip`** during extension handling to allow clean installation. |
| `TypeError: tuple indices must be integers` | Scanner output schema mismatch | Resolved in current version; ensure you are running the latest codebase. |

---

## ⚖️ Legal & Ethical Scope

This toolkit is designed and intended strictly for:
1. **Authorized Security Research** on applications you own or have explicit authorization to test under a formal engagement.
2. **Defensive Auditing, Vulnerability Assessment & Educational Reverse Engineering**.

> Redistributing copyrighted App Store or TestFlight binaries without authorization violates Apple's Terms of Service and applicable intellectual property laws. Runtime decryption requires explicit user acknowledgment (`--i-own-this-build`).
