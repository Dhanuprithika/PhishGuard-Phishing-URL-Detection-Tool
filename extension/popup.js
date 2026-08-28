const BACKEND_URL = "http://127.0.0.1:8000/api/scan";
const WEBAPP_URL = "http://localhost:5173"; // Or Vite port 8443

let currentUrl = "";
let latestResult = null;

// DOM Elements
const targetUrlEl = document.getElementById("target-url");
const stateIdle = document.getElementById("state-idle");
const stateScanning = document.getElementById("state-scanning");
const stateResult = document.getElementById("state-result");
const stateError = document.getElementById("state-error");
const errorMessageEl = document.getElementById("error-message");

const btnScan = document.getElementById("btn-scan");
const btnRescan = document.getElementById("btn-rescan");
const btnRetry = document.getElementById("btn-retry");
const btnViewReport = document.getElementById("btn-view-report");

const verdictBanner = document.getElementById("verdict-banner");
const verdictBadge = document.getElementById("verdict-badge");
const scoreVal = document.getElementById("score-val");
const verdictSummary = document.getElementById("verdict-summary");
const meterScoreText = document.getElementById("meter-score-text");
const meterFill = document.getElementById("meter-fill");
const threatSection = document.getElementById("threat-section");
const threatList = document.getElementById("threat-list");

function showState(state) {
  stateIdle.classList.add("hidden");
  stateScanning.classList.add("hidden");
  stateResult.classList.add("hidden");
  stateError.classList.add("hidden");

  if (state === "idle") stateIdle.classList.remove("hidden");
  if (state === "scanning") stateScanning.classList.remove("hidden");
  if (state === "result") stateResult.classList.remove("hidden");
  if (state === "error") stateError.classList.remove("hidden");
}

// Get active tab URL on popup load
async function initTab() {
  try {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        currentUrl = tab.url;
        targetUrlEl.textContent = currentUrl;

        // Ignore internal chrome/edge pages
        if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("edge://") || currentUrl.startsWith("about:")) {
          targetUrlEl.textContent = "Browser system page (Skipped)";
          showState("idle");
          btnScan.disabled = true;
          return;
        }

        // Automatically trigger scan for quick real-time protection
        startScan(currentUrl);
        return;
      }
    }
  } catch (err) {
    console.warn("Could not query active tab:", err);
  }

  // Fallback demo URL if opened outside standard extension tab context
  currentUrl = "https://github.com";
  targetUrlEl.textContent = currentUrl;
  showState("idle");
}

async function startScan(urlToScan) {
  showState("scanning");

  try {
    const response = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan }),
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    latestResult = data;
    renderResult(data);
  } catch (error) {
    console.error("Scan failed:", error);
    errorMessageEl.textContent = `Could not reach PhishGuard API. Please ensure the backend server is running on http://127.0.0.1:8000.`;
    showState("error");
  }
}

function renderResult(result) {
  const score = result.riskScore !== undefined ? result.riskScore : result.risk_score;
  const verdict = result.verdict || "safe";

  // Banner classes
  verdictBanner.className = `verdict-banner ${verdict}`;
  meterFill.className = `meter-fill ${verdict}`;
  meterFill.style.width = `${Math.max(4, score)}%`;

  scoreVal.textContent = score;

  if (verdict === "safe") {
    verdictBadge.className = "verdict-badge safe";
    verdictBadge.textContent = "● SAFE";
    meterScoreText.textContent = "Low Risk";
  } else if (verdict === "suspicious") {
    verdictBadge.className = "verdict-badge suspicious";
    verdictBadge.textContent = "▲ SUSPICIOUS";
    meterScoreText.textContent = "Medium Risk";
  } else {
    verdictBadge.className = "verdict-badge phishing";
    verdictBadge.textContent = "✕ HIGH RISK";
    meterScoreText.textContent = "High Risk";
  }

  verdictSummary.textContent = result.explanation || "Scan completed.";

  // Render threats if present
  if (result.indicators && result.indicators.length > 0 && verdict !== "safe") {
    threatSection.classList.remove("hidden");
    threatList.innerHTML = "";
    result.indicators.slice(0, 3).forEach((ind) => {
      const item = document.createElement("div");
      item.className = "threat-item";
      item.textContent = `• ${ind}`;
      threatList.appendChild(item);
    });
  } else {
    threatSection.classList.add("hidden");
  }

  showState("result");
}

// Event Listeners
btnScan?.addEventListener("click", () => startScan(currentUrl));
btnRescan?.addEventListener("click", () => startScan(currentUrl));
btnRetry?.addEventListener("click", () => startScan(currentUrl));

btnViewReport?.addEventListener("click", () => {
  const destination = `${WEBAPP_URL}/?url=${encodeURIComponent(currentUrl)}`;
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
    chrome.tabs.create({ url: destination });
  } else {
    window.open(destination, "_blank");
  }
});

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", initTab);
