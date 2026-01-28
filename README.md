🧠 Deep-C

Deep-C is an Android Deep Link Exploitation Framework that automatically decompiles APKs, identifies insecure deep link entry points, maps real-world attack scenarios, and generates executable adb Proof-of-Concepts (PoCs).
It is designed for mobile application penetration testing, red team assessments, and security research.

<img width="1023" height="790" alt="image" src="https://github.com/user-attachments/assets/f5cdc5ef-65b5-4447-bd6f-bac3cf9459f5" />



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

<img width="452" height="476" alt="image" src="https://github.com/user-attachments/assets/d0027d1a-b315-4ae0-a887-f71151ff78d1" />

🔧 Requirements

Make sure the following tools are installed and available in your PATH:

Python 3.8+
apktool
adb (Android Platform Tools)

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
