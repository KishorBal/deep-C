# Deep-C

**Deep-C** is an **Android Deep Link Exploitation Framework** that automatically decompiles APKs, identifies exposed and insecure deep link entry points, validates exploitability using **static analysis and optional AI verification**, and generates executable **adb Proof-of-Concepts (PoCs)**.

Deep-C is designed for **mobile application penetration testing**, **red team assessments**, and **Android security research**, with a strong focus on **real-world exploitability** rather than noisy findings.

<img width="1225" height="731" alt="image" src="https://github.com/user-attachments/assets/ac5fc7a9-2ba6-4228-951f-1a351415c163" />

---

## ✨ Features

### 📦 APK Analysis
- Automatic APK decompilation using **apktool**
- Bytecode processing using **dex2jar**
- Java source recovery using **jadx**

---

### 🔍 Deep Link Discovery
- Custom scheme deep links
- App links (`http` / `https`)
- Exported and browsable activities
- Intent filter analysis (`VIEW` + `BROWSABLE`)

---

### 🚪 Exported Component Detection
- Exported activity identification
- Deep link entry-point enumeration
- Custom scheme reachability analysis

---

### 🌐 WebView Abuse Identification
- Detection of attacker-controlled data reaching `WebView.loadUrl`
- Identification of unsafe URL handling
- Java & Kotlin (jadx-decompiled) code support

---

### ⚠️ Insecure Deep Link Pattern Detection
- Missing or improper host validation
- Weak validation logic (`endsWith`, `contains`, regex)
- Unsafe custom scheme handling
- Sensitive paths:
  - login
  - reset
  - wallet
  - payment
  - admin / privileged flows

---

### 🎯 Attack Mapping
- Intent hijacking
- Open redirects
- Authentication bypass via deep links
- WebView URL injection
- Arbitrary URL loading

---

### 🤖 AI-Assisted Vulnerability Verification (Optional)
- Optional **ChatGPT-based AI review** (`--ai-review`)
- AI acts as a **second-pass security reviewer**
- Confirms exploitability based on:
  - Decompiled source code
  - Intent data flow
  - Validation logic
- Reduces false positives
- AI **never invents findings** — it only validates existing ones
- AI verdict is merged safely with static confidence

> AI integration is **opt-in** and disabled by default.

---

### 🧪 Proof-of-Concept (PoC) Generation
- Scheme-aware PoC generation
- Custom scheme handling
- Multiple payload variants:
  - external URLs
  - `javascript:` payloads
- Executable adb commands
- Optional auto-execution of PoCs

---

### 📤 Output & Reporting
- Clear, human-readable **console output**
- Structured **JSON result file**
- Includes:
  - Static confidence
  - AI confidence (if enabled)
  - Final merged confidence
  - Reasoning
  - Generated PoCs


**How Deep-C Works**
## 🔄 High-Level Workflow

```
APK
 ↓
Decompile APK (apktool)
 ↓
Extract Manifest & Bytecode
 ↓
Identify Exported Deep Link Entry Points
 ↓
Decompile Source (dex2jar + jadx)
 ↓
Validate Exploitability (code / heuristics)
 ↓
(Optional) AI Verification (--ai-review)
 ↓
Generate adb PoCs
 ↓
Console Output + JSON Report
```
🔧 Requirements

Make sure the following tools are installed and available in your PATH:

Python 3.8+
apktool
adb (Android Platform Tools)
d2j-dex2jar
openai

**Verify Installation**
apktool --version
adb version
python3 --version

**For AI Based analysis (openAI)**

Export your openAI API key to the enviornment variables

```
export OPENAI_API_KEY="Your_openai_API_key"
```

**Usage**

🔍 Analyze APK (No Exploitation)
python deepc.py -a target.apk

💥 Analyze + Execute PoCs via adb
python deepc.py -a target.apk --exec

⚠️ Ensure a device/emulator is connected via adb before using --exec.
