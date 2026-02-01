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

                ┌──────────────────┐
                │      APK Input   │
                └────────┬─────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │ APK Decompilation (apktool)     │
        │ - AndroidManifest.xml           │
        │ - classes.dex                   │
        └────────┬───────────────────────┘
                 │
                 ▼
        ┌────────────────────────────────┐
        │ Bytecode Processing             │
        │ - dex2jar (DEX → JAR)           │
        │ - jadx (JAR → Java source)      │
        └────────┬───────────────────────┘
                 │
                 ▼
        ┌────────────────────────────────┐
        │ Manifest Analysis               │
        │ - Exported activities           │
        │ - VIEW + BROWSABLE intent       │
        │ - scheme / host / path          │
        └────────┬───────────────────────┘
                 │
                 ▼
        ┌────────────────────────────────┐
        │ Candidate Deep Link Entry Point │
        └────────┬───────────────────────┘
                 │
                 ▼
        ┌────────────────────────────────┐
        │ Activity Source Resolution      │
        │ - Map activity → .java file     │
        │ - (jadx output)                 │
        └────────┬───────────────────────┘
                 │
        ┌────────▼────────┐
        │ Source Found?   │
        └───────┬────────┘
                │
        ┌───────▼──────────┐        ┌───────────────────────────┐
        │ YES               │        │ NO                        │
        │ (Code Available)  │        │ (Source unresolved)       │
        └───────┬──────────┘        └───────────┬──────────────┘
                │                                 │
                ▼                                 ▼
 ┌──────────────────────────────┐    ┌──────────────────────────────┐
 │ Static Code Review            │    │ Heuristic Assessment          │
 │ - intent.getData()            │    │ - Exported + browsable        │
 │ - getQueryParameter("X")      │    │ - No code visibility          │
 │ - getStringExtra("X")         │    │                              │
 │ - WebView.loadUrl()           │    │                              │
 │ - Validation checks           │    │                              │
 └────────┬─────────────────────┘    └───────────┬──────────────────┘
          │                                      │
          ▼                                      ▼
┌──────────────────────┐        ┌──────────────────────────┐
│ Parameter Found?     │        │ Generic Parameter Probe  │
└───────┬─────────────┘        │ - url / redirect / next  │
        │                      │ - heuristic only          │
┌───────▼─────────────┐        └───────────┬──────────────┘
│ YES                  │                    │
│ (Code-derived)       │                    ▼
└───────┬─────────────┘        ┌──────────────────────────┐
        │                      │ Confidence: MEDIUM        │
        ▼                      └──────────────────────────┘
┌──────────────────────────────┐
│ Validation Strength Analysis │
│ - Weak (endsWith, contains)  │
│ - Strong (host allowlist)    │
└────────┬─────────────────────┘
         ▼
┌──────────────────────────────┐
│ Confidence Assignment        │
│ - HIGH  → code + weak/no val │
│ - MEDIUM→ partial / unclear  │
│ - LOW   → strong validation  │
└────────┬─────────────────────┘
         ▼
┌──────────────────────────────┐
│ PoC Generation               │
│ - Scheme-aware URL building  │
│ - No hardcoded hosts         │
│ - adb VIEW intent            │
│ - Optional component launch  │
└────────┬─────────────────────┘
         ▼
┌──────────────────────────────┐
│ Output                        │
│ - Human-readable stdout       │
│ - deepc_result.json           │
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
