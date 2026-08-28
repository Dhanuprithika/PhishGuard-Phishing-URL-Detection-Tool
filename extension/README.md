# PhishGuard Browser Extension

Real-time browser extension for phishing URL detection powered by the PhishGuard FastAPI detection engine.

## Features

- **One-Click Active Tab Inspection**: Automatically detects and scans the URL of the current open tab.
- **Explainable Verdicts**: Displays `SAFE` (green), `SUSPICIOUS` (orange), or `HIGH RISK` (red) with a 0–100 risk score meter.
- **Threat Indicator Summary**: Highlights red flags (e.g. brand impersonation, lack of HTTPS, lookalike domain, free TLDs).
- **Deep Report Integration**: One-click **"View Full Report →"** button opens the PhishGuard web application loaded with the full structural and domain analysis.

## How to Install in Chrome / Edge / Brave

1. Open your browser and navigate to:
   - **Chrome / Brave**: `chrome://extensions`
   - **Microsoft Edge**: `edge://extensions`
2. Enable **Developer mode** (toggle in the top-right or sidebar).
3. Click **"Load unpacked"**.
4. Select the `extension/` folder inside this repository.
5. Pin **PhishGuard** to your browser toolbar.

## Prerequisites

Ensure the PhishGuard FastAPI backend is running locally:
```bash
# From project root
py -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
