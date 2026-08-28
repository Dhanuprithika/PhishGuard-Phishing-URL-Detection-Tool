import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from .models import ScanRequest, ScanResponse
from .detection.engine import analyze_url
from .detection.features import extract_url_features

app = FastAPI(
    title="PhishGuard API",
    description="Intelligent Phishing URL Detection & Cyber Threat Intelligence API",
    version="1.0.0"
)

# Enable CORS for local Vite dev server, production origin, and browser extension (chrome-extension://)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "PhishGuard Phishing URL Detection Tool",
        "version": "1.0.0"
    }

@app.post("/api/scan", response_model=ScanResponse, tags=["Scanner"])
def scan_url(request: ScanRequest):
    """
    Analyzes a URL for phishing, credential theft, lookalikes, and cybersecurity threats.
    """
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL parameter cannot be empty."
        )

    try:
        result = analyze_url(raw_url)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing URL: {str(e)}"
        )

@app.post("/api/features", tags=["Features"])
def get_features(request: ScanRequest):
    """
    Extracts granular lexical, structural, and semantic features for a given URL.
    """
    return extract_url_features(request.url)

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
