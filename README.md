# PhishGuard — Phishing URL Detection Tool with Browser Extension Integration

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20Vite-61DAFB.svg)](https://react.dev)
[![TailwindCSS](https://img.shields.io/badge/Styling-Tailwind%20v4-38B2AC.svg)](https://tailwindcss.com)
[![Extension](https://img.shields.io/badge/Extension-Manifest%20V3-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)

**PhishGuard** is an end-to-end cybersecurity intelligence tool designed to detect phishing websites, lookalike domains, brand impersonation, and fraudulent URLs before users become victims of credential harvesting or malware attacks.

---

## 🎯 Architecture Overview

```text
PhishGuard/
├── backend/                  # FastAPI Python Backend & Detection Engine
│   ├── detection/
│   │   ├── features.py       # Lexical, structural & entropy feature extractor
│   │   ├── heuristics.py     # Rule-based scoring & threat indicator engine
│   │   ├── domain_intel.py   # Safe DNS resolution & WHOIS domain age lookup
│   │   ├── ssl_cert.py       # Safe TLS handshake & certificate validator
│   │   ├── reputation.py     # Local threat intelligence & blacklist database
│   │   ├── ml_classifier.py  # Lightweight ML classifier (RandomForest)
│   │   └── engine.py         # Multi-layered scoring orchestrator
│   ├── main.py               # FastAPI application (/api/scan, /api/health)
│   ├── models.py             # Pydantic schemas for requests and responses
│   └── requirements.txt      # Python dependencies
│
├── extension/                # Manifest V3 Chrome/Edge Browser Extension
│   ├── manifest.json         # Extension manifest V3
│   ├── popup.html            # Extension popup UI
│   ├── popup.css             # Extension styling (matching Figma design)
│   ├── popup.js              # Active tab retrieval & API integration
│   └── icons/                # Extension icons (16, 32, 48, 128)
│
├── src/                      # Figma-generated React 19 Frontend
│   ├── components/           # Reusable UI components (RiskMeter, VerdictBadge, CheckList)
│   ├── screens/              # HomeScreen, ScanningScreen, ResultScreen, AnalysisScreen, HistoryScreen, ExtensionScreen
│   ├── services/             # API client layer connecting to backend
│   └── types.ts              # Core TypeScript interfaces
│
├── .gitignore                # Git safety configuration
└── vite.config.ts            # Vite 8 configuration
```

---

## 🚀 Quick Start Guide

### 1. Start the FastAPI Backend

```bash
# Install backend dependencies
py -m pip install -r backend/requirements.txt

# Start FastAPI server on port 8000
py -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive API documentation will be available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

### 2. Run the Web Application

```bash
# Install node dependencies
npm install

# Start Vite development server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) (or the Vite preview port) in your browser.

### 3. Load the Browser Extension

1. Open **Chrome** or **Edge** and go to `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** toggle.
3. Click **"Load unpacked"** and select the `extension/` folder in this repository.
4. Pin the **PhishGuard** shield icon to your browser bar.

---

## 🔍 Detection Engine Capabilities

- **Lexical & Structural Analysis**: Evaluates URL length, subdomain depth, entropy, obfuscation, non-standard ports, and credential keywords.
- **Brand Impersonation**: Detects typosquatting, character replacement (e.g. `paypa1`, `goog1e`), and deceptive subdomains (`paypal.secure-login.net`).
- **Safe SSL / TLS Verification**: Verifies certificate validity, issuer, and expiration without downloading untrusted payloads.
- **Domain Intelligence**: Safe DNS resolution (A/MX records) and WHOIS domain age inspection.
- **Threat Reputation**: Local threat feed matching active phishing campaigns.
- **Machine Learning**: Random Forest classification on multidimensional feature vectors.
- **Explainable Verdict**: Clear 0–100 score, categorized signals, and actionable security recommendations.

---

## 🧪 Test Scenarios

| Test URL | Expected Verdict | Expected Score | Key Reasons |
| :--- | :--- | :--- | :--- |
| `https://github.com` | **SAFE** | 2–5 / 100 | Established domain, valid TLS, clean reputation |
| `https://dropbox-share.files.net/doc` | **SUSPICIOUS** | 45–65 / 100 | Brand impersonation in subdomain, non-official domain |
| `http://paypa1-verify.tk/login` | **HIGH RISK** | 90–99 / 100 | Typosquatting (Paypal), unencrypted HTTP, suspicious TLD (.tk) |
| `http://192.168.1.1/admin/verify?paypal=1` | **HIGH RISK** | 90–99 / 100 | Raw IP hostname, no HTTPS, credential query parameters |
