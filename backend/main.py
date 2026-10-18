"""
FastAPI Server for Chrome Extension Phishing Detection.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.services.url_detector import detect_url_phishing, load_model
from contextlib import asynccontextmanager
from backend.services.email_detector import detect_email_phishing, load_email_nlp_model


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-warm models into memory on startup."""
    try:
        load_model()
        print("[Startup] XGBoost URL Phishing model loaded successfully.")
    except Exception as exc:
        print(f"[Startup Warning] Could not preload URL model: {exc}")

    try:
        load_email_nlp_model()
        print("[Startup] Email Phishing NLP model loaded successfully.")
    except Exception as exc:
        print(f"[Startup Warning] Could not preload Email NLP model: {exc}")
    yield


app = FastAPI(
    title="Phishing Shield Detection API",
    description="Backend ML and heuristic analysis for Chrome extension protection",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for Chrome Extension origins and localhost
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://.*|http://localhost:.*|http://127\.0\.0\.1:.*)$",
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UrlCheckRequest(BaseModel):
    url: str = Field(...)


class UrlCheckResponse(BaseModel):
    url: str
    resolved_url: Optional[str] = None
    is_shortened: Optional[bool] = False
    threat_score: float
    verdict: str
    risk_level: str
    ml_probability: float
    reasons: List[str]


class BatchUrlCheckRequest(BaseModel):
    urls: List[str] = Field(..., max_length=50)


class BatchUrlCheckResponse(BaseModel):
    results: List[UrlCheckResponse]
    total: int
    phishing_count: int
    suspicious_count: int


class EmailCheckRequest(BaseModel):
    sender_name: str = Field(default="")
    sender_email: str = Field(default="")
    subject: str = Field(default="")
    body_text: str = Field(default="")
    links: Optional[List[str]] = Field(default_factory=list)


class EmailCheckResponse(BaseModel):
    threat_score: float
    verdict: str
    risk_level: str
    reasons: List[str]
    link_count: int
    analyzed_links: List[dict]
    nlp_analysis: Optional[dict] = None


@app.get("/api/health")
def health_check():
    from backend.services.heuristics import POPULAR_BRANDS
    from backend.services.email_detector import load_email_nlp_model
    return {
        "status": "healthy",
        "service": "phishing-shield-api",
        "version": "1.0.0",
        "popular_brands": POPULAR_BRANDS,
        "email_nlp_model_loaded": load_email_nlp_model() is not None
    }


@app.post("/api/check-url", response_model=UrlCheckResponse)
def check_url_endpoint(payload: UrlCheckRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    try:
        result = detect_url_phishing(payload.url)
        return UrlCheckResponse(
            url=result["url"],
            resolved_url=result.get("resolved_url"),
            is_shortened=result.get("is_shortened", False),
            threat_score=result["threat_score"],
            verdict=result["verdict"],
            risk_level=result["risk_level"],
            ml_probability=result["ml_probability"],
            reasons=result["reasons"]
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(exc)}")


@app.post("/api/check-urls", response_model=BatchUrlCheckResponse)
def check_urls_batch_endpoint(payload: BatchUrlCheckRequest):
    from concurrent.futures import ThreadPoolExecutor

    def process_one(u: str) -> UrlCheckResponse:
        u_clean = u.strip()
        if not u_clean:
            return UrlCheckResponse(
                url=u,
                threat_score=0.0,
                verdict="safe",
                risk_level="LOW",
                ml_probability=0.0,
                reasons=[]
            )
        try:
            res = detect_url_phishing(u_clean)
            return UrlCheckResponse(
                url=res["url"],
                resolved_url=res.get("resolved_url"),
                is_shortened=res.get("is_shortened", False),
                threat_score=res["threat_score"],
                verdict=res["verdict"],
                risk_level=res["risk_level"],
                ml_probability=res["ml_probability"],
                reasons=res["reasons"]
            )
        except Exception:
            return UrlCheckResponse(
                url=u,
                threat_score=50.0,
                verdict="suspicious",
                risk_level="MEDIUM",
                ml_probability=0.5,
                reasons=["Analysis error during batch evaluation"]
            )

    worker_count = min(max(len(payload.urls), 1), 10)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = list(executor.map(process_one, payload.urls))

    phishing_count = sum(1 for r in results if r.verdict == "phishing")
    suspicious_count = sum(1 for r in results if r.verdict == "suspicious")

    return BatchUrlCheckResponse(
        results=results,
        total=len(results),
        phishing_count=phishing_count,
        suspicious_count=suspicious_count
    )


@app.post("/api/check-email", response_model=EmailCheckResponse)
def check_email_endpoint(payload: EmailCheckRequest):
    try:
        result = detect_email_phishing(
            sender_name=payload.sender_name,
            sender_email=payload.sender_email,
            subject=payload.subject,
            body_text=payload.body_text,
            links=payload.links
        )
        return EmailCheckResponse(
            threat_score=result["threat_score"],
            verdict=result["verdict"],
            risk_level=result["risk_level"],
            reasons=result["reasons"],
            link_count=result["link_count"],
            analyzed_links=result["analyzed_links"],
            nlp_analysis=result.get("nlp_analysis")
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email analysis error: {str(exc)}")


if __name__ == "__main__":
    import os
    import uvicorn
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("backend.main:app", host=host, port=port, reload=True)

