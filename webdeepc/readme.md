# 🧠 Deep-C AI — Web Edition
<img width="1661" height="807" alt="image" src="https://github.com/user-attachments/assets/5e667c19-0048-4ce2-bf17-f992a4b889da" />

> Advanced Android Deep Link Security Auditor  
> Built for mobile penetration testers & red teamers  

Deep-C AI Web is the modern dashboard interface for the Deep-C Android Deep Link Exploitation Framework.

It provides a premium glass-style UI for uploading APKs, analyzing deep link vulnerabilities, validating weak host checks, and reviewing AI-assisted findings.

---

## ✨ Features

- 📦 Drag & Drop APK upload
- 🔍 Automatic Deep Link Discovery
- ⚠️ Weak Host Validation Detection
- 🧠 Optional AI Review
- 💻 ADB Exploit PoC Generation
- 📊 Clean Dashboard View (High-level logs only)
- 🎨 Glassmorphism Security UI

---

# ⚙️ Installation

## 1️⃣ Backend Setup (FastAPI)

### Create Virtual Environment

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
```
Install Dependencies
```
pip install fastapi uvicorn python-multipart openai
```
## Run Backend
```
uvicorn main:app --reload
```
## Frontend Setup (React + Vite + Tailwind)
```
cd frontend
npm install
npm run dev
```

