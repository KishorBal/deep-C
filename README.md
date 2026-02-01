🧠 Deep-C

Deep-C is an Android Deep Link Exploitation Framework that automatically decompiles APKs, identifies insecure deep link entry points, maps real-world attack scenarios, and generates executable adb Proof-of-Concepts (PoCs).
It is designed for mobile application penetration testing, red team assessments, and security research.

<img width="1279" height="627" alt="image" src="https://github.com/user-attachments/assets/cfd0fb65-251c-42f2-a4df-a366c7576a21" />




✨ Features

📦 Automatic APK Decompilation using apktool
🔍 Deep Link Discovery
Custom schemes
App links (http/https)
Exported activities
🚪 Exported Component Detection
🌐 WebView Abuse Identification
⚠️ Insecure Deep Link Pattern Detection
Missing host validation
Custom schemes

Sensitive paths (login, reset, wallet, payment, etc.)
🎯 Attack Mapping
Intent hijacking
Open redirects
Authentication bypass
WebView URL injection

💥 adb-based PoC Generation

▶️ Optional Auto-Execution of PoCs

**How Deep-C Works**

    ┌───────────┐
│ APK │
└─────┬─────┘
│
▼
┌──────────────────────────────┐
│ APK Decompilation │
│ (apktool) │
└─────────────┬────────────────┘
│
▼
┌──────────────────────────────┐
│ Manifest & Bytecode │
│ Extraction │
└─────────────┬────────────────┘
│
▼
┌──────────────────────────────┐
│ Deep Link Entry Point │
│ Identification │
│ (exported + browsable) │
└─────────────┬────────────────┘
│
▼
┌──────────────────────────────┐
│ Source Decompilation │
│ (dex2jar + jadx) │
└─────────────┬────────────────┘
│
▼
┌──────────────────────────────┐
│ Exploitability Validation │
│ • Code analysis │
│ • Heuristics (fallback) │
└─────────────┬────────────────┘
│
▼
┌──────────────────────────────┐
│ PoC Generation │
│ (adb commands) │
└─────────────┬────────────────┘
│
▼
┌──────────────────────────────┐
│ Results Output │
│ • Console (stdout) │
│ • JSON file │
└──────────────────────────────┘

🔧 Requirements

Make sure the following tools are installed and available in your PATH:

Python 3.8+
apktool
adb (Android Platform Tools)
d2j-dex2jar

**Verify Installation**
apktool --version
adb version
python3 --version

**Usage**

🔍 Analyze APK (No Exploitation)
python deepc.py -a target.apk

💥 Analyze + Execute PoCs via adb
python deepc.py -a target.apk --exec

⚠️ Ensure a device/emulator is connected via adb before using --exec.
