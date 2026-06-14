"""
Scan Router
Handles URL scanning, email scanning, history, and statistics.
"""

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.schemas import (
    URLScanRequest,
    EmailScanRequest,
    ScanResultResponse,
    ScanHistoryItem,
    ScanHistoryResponse,
    UserStatsResponse,
    FeatureDetail,
)
from app.services.url_analyzer import (
    extract_url_features,
    enrich_features_with_external_data,
    get_numeric_features,
)
from app.services.email_analyzer import analyze_email_content, calculate_email_risk_score
from app.services.ml_predictor import predict_phishing
from app.utils.security import get_current_user
from app.utils.helpers import classify_risk_level, classify_verdict, generate_recommendations

router = APIRouter(prefix="/api/scan", tags=["Scanning"])


@router.post("/url", response_model=ScanResultResponse)
async def scan_url(
    request: URLScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Scan a URL for phishing indicators.
    Extracts 30+ features, runs ML prediction, and returns detailed analysis.
    """
    url = request.url.strip()

    # Step 1: Extract basic URL features
    features = extract_url_features(url)

    # Step 2: Enrich with external data (WHOIS, SSL, DNS)
    try:
        features = await enrich_features_with_external_data(url, features)
    except Exception:
        # If external lookups fail, continue with basic features
        features.setdefault("domain_age_days", -1)
        features.setdefault("is_new_domain", False)
        features.setdefault("ssl_valid", False)
        features.setdefault("ssl_issuer", "unknown")
        features.setdefault("ssl_days_remaining", -1)
        features.setdefault("has_dns_record", False)
        features.setdefault("dns_record_count", 0)

    # Step 3: Convert to numeric vector and predict
    feature_vector = get_numeric_features(features)
    prediction = predict_phishing(feature_vector)

    risk_score = prediction["risk_score"]
    confidence = prediction["confidence"]
    verdict = prediction["verdict"]
    risk_level = classify_risk_level(risk_score)

    # Step 4: Build feature details for the response
    feature_details = _build_url_feature_details(features)

    # Step 5: Generate recommendations
    recommendations = generate_recommendations(verdict, features)

    # Step 6: Save scan result to database
    scan = Scan(
        user_id=current_user.id,
        scan_type="url",
        input_data=url,
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        details_json=json.dumps({
            "features": {k: v for k, v in features.items() if not isinstance(v, (list, dict))},
            "prediction_method": prediction.get("method", "unknown"),
        }),
    )
    db.add(scan)
    await db.flush()

    return ScanResultResponse(
        id=scan.id,
        scan_type="url",
        input_data=url,
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        risk_level=risk_level,
        features=feature_details,
        recommendations=recommendations,
        created_at=scan.created_at,
    )


@router.post("/email", response_model=ScanResultResponse)
async def scan_email(
    request: EmailScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Scan email content for phishing indicators.
    Analyzes urgency, social engineering phrases, embedded links, and more.
    """
    # Analyze email content
    features = analyze_email_content(
        email_content=request.email_content,
        subject=request.subject,
        sender=request.sender,
    )

    # Calculate risk score
    risk_score = calculate_email_risk_score(features)
    verdict = classify_verdict(risk_score)
    risk_level = classify_risk_level(risk_score)
    confidence = 0.70  # Fixed confidence for rule-based email analysis

    # Build feature details
    feature_details = _build_email_feature_details(features)

    # Generate recommendations
    recommendations = generate_recommendations(verdict, features)

    # Save to database
    scan = Scan(
        user_id=current_user.id,
        scan_type="email",
        input_data=request.email_content[:500],  # Truncate for storage
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        details_json=json.dumps({
            "features": {k: v for k, v in features.items() if not isinstance(v, list)},
            "subject": request.subject,
            "sender": request.sender,
        }),
    )
    db.add(scan)
    await db.flush()

    return ScanResultResponse(
        id=scan.id,
        scan_type="email",
        input_data=request.email_content[:500],
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        risk_level=risk_level,
        features=feature_details,
        recommendations=recommendations,
        created_at=scan.created_at,
    )


@router.get("/history", response_model=ScanHistoryResponse)
async def get_scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    scan_type: Optional[str] = Query(None, pattern="^(url|email)$"),
    verdict: Optional[str] = Query(None, pattern="^(SAFE|SUSPICIOUS|PHISHING)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get paginated scan history for the current user."""
    # Build query
    query = select(Scan).where(Scan.user_id == current_user.id)
    count_query = select(func.count(Scan.id)).where(Scan.user_id == current_user.id)

    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
        count_query = count_query.where(Scan.scan_type == scan_type)

    if verdict:
        query = query.where(Scan.verdict == verdict)
        count_query = count_query.where(Scan.verdict == verdict)

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * page_size
    query = query.order_by(desc(Scan.created_at)).offset(offset).limit(page_size)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanHistoryResponse(
        scans=[
            ScanHistoryItem(
                id=scan.id,
                scan_type=scan.scan_type,
                input_data=scan.input_data,
                risk_score=scan.risk_score,
                verdict=scan.verdict,
                created_at=scan.created_at,
            )
            for scan in scans
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanResultResponse)
async def get_scan_detail(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed results for a specific scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    # Parse stored details
    details = json.loads(scan.details_json or "{}")
    features_data = details.get("features", {})

    # Rebuild feature details from stored data
    if scan.scan_type == "url":
        feature_details = _build_url_feature_details(features_data)
    else:
        feature_details = _build_email_feature_details(features_data)

    recommendations = generate_recommendations(scan.verdict, features_data)

    return ScanResultResponse(
        id=scan.id,
        scan_type=scan.scan_type,
        input_data=scan.input_data,
        risk_score=scan.risk_score,
        verdict=scan.verdict,
        confidence=scan.confidence,
        risk_level=classify_risk_level(scan.risk_score),
        features=feature_details,
        recommendations=recommendations,
        created_at=scan.created_at,
    )


@router.get("/", response_model=UserStatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get threat statistics for the current user."""
    user_scans = select(Scan).where(Scan.user_id == current_user.id)

    # Total scans
    total_result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id)
    )
    total_scans = total_result.scalar() or 0

    if total_scans == 0:
        return UserStatsResponse(
            total_scans=0,
            safe_count=0,
            suspicious_count=0,
            phishing_count=0,
            urls_scanned=0,
            emails_scanned=0,
            average_risk_score=0.0,
        )

    # Verdict counts
    verdict_counts = {}
    for v in ["SAFE", "SUSPICIOUS", "PHISHING"]:
        r = await db.execute(
            select(func.count(Scan.id)).where(
                Scan.user_id == current_user.id, Scan.verdict == v
            )
        )
        verdict_counts[v] = r.scalar() or 0

    # Type counts
    url_count_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.user_id == current_user.id, Scan.scan_type == "url"
        )
    )
    email_count_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.user_id == current_user.id, Scan.scan_type == "email"
        )
    )

    # Average risk score
    avg_result = await db.execute(
        select(func.avg(Scan.risk_score)).where(Scan.user_id == current_user.id)
    )

    # Last scan
    last_scan_result = await db.execute(
        select(func.max(Scan.created_at)).where(Scan.user_id == current_user.id)
    )

    return UserStatsResponse(
        total_scans=total_scans,
        safe_count=verdict_counts.get("SAFE", 0),
        suspicious_count=verdict_counts.get("SUSPICIOUS", 0),
        phishing_count=verdict_counts.get("PHISHING", 0),
        urls_scanned=url_count_result.scalar() or 0,
        emails_scanned=email_count_result.scalar() or 0,
        average_risk_score=round(avg_result.scalar() or 0.0, 1),
        last_scan_at=last_scan_result.scalar(),
    )


def _build_url_feature_details(features: dict) -> list[FeatureDetail]:
    """Build human-readable feature details for URL scans."""
    details = []

    # IP Address check
    if features.get("has_ip_address"):
        details.append(FeatureDetail(
            name="IP Address URL",
            value=True,
            risk_contribution="high",
            description="URL uses a raw IP address instead of a domain name",
        ))

    # HTTPS check
    is_https = features.get("is_https", False)
    details.append(FeatureDetail(
        name="HTTPS Encryption",
        value=is_https,
        risk_contribution="low" if is_https else "high",
        description="Connection is encrypted with HTTPS" if is_https else "No HTTPS encryption — connection is not secure",
    ))

    # Domain age
    domain_age = features.get("domain_age_days")
    if domain_age is not None and domain_age >= 0:
        risk = "high" if domain_age < 30 else ("medium" if domain_age < 180 else "low")
        details.append(FeatureDetail(
            name="Domain Age",
            value=f"{domain_age} days",
            risk_contribution=risk,
            description=f"Domain was registered {domain_age} days ago",
        ))

    # SSL Certificate
    ssl_valid = features.get("ssl_valid", False)
    details.append(FeatureDetail(
        name="SSL Certificate",
        value="Valid" if ssl_valid else "Invalid/Missing",
        risk_contribution="low" if ssl_valid else "medium",
        description=f"SSL issued by {features.get('ssl_issuer', 'unknown')}" if ssl_valid else "SSL certificate is invalid or missing",
    ))

    # Suspicious keywords
    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count > 0:
        details.append(FeatureDetail(
            name="Suspicious Keywords",
            value=kw_count,
            risk_contribution="medium" if kw_count < 3 else "high",
            description=f"Found {kw_count} suspicious keyword(s) in URL",
        ))

    # Suspicious TLD
    if features.get("is_suspicious_tld"):
        details.append(FeatureDetail(
            name="Suspicious TLD",
            value=features.get("tld", ""),
            risk_contribution="high",
            description=f"The TLD '.{features.get('tld', '')}' is commonly used in phishing",
        ))

    # URL length
    url_length = features.get("url_length", 0)
    if url_length > 75:
        details.append(FeatureDetail(
            name="URL Length",
            value=url_length,
            risk_contribution="medium" if url_length < 150 else "high",
            description=f"URL is {url_length} characters long — phishing URLs tend to be longer",
        ))

    # Subdomains
    subdomain_count = features.get("subdomain_count", 0)
    if subdomain_count > 2:
        details.append(FeatureDetail(
            name="Subdomain Count",
            value=subdomain_count,
            risk_contribution="medium",
            description=f"URL has {subdomain_count} subdomains — excessive subdomains are suspicious",
        ))

    # DNS record
    has_dns = features.get("has_dns_record", True)
    if not has_dns:
        details.append(FeatureDetail(
            name="DNS Records",
            value="Missing",
            risk_contribution="high",
            description="No DNS records found for this domain",
        ))

    return details


def _build_email_feature_details(features: dict) -> list[FeatureDetail]:
    """Build human-readable feature details for email scans."""
    details = []

    # Urgency
    urgency_count = features.get("urgency_keyword_count", 0)
    if urgency_count > 0:
        details.append(FeatureDetail(
            name="Urgency Language",
            value=urgency_count,
            risk_contribution="medium" if urgency_count < 3 else "high",
            description=f"Found {urgency_count} urgency keyword(s) designed to pressure quick action",
        ))

    # Social engineering
    se_count = features.get("social_engineering_count", 0)
    if se_count > 0:
        details.append(FeatureDetail(
            name="Social Engineering",
            value=se_count,
            risk_contribution="high",
            description=f"Found {se_count} social engineering phrase(s) commonly used in phishing",
        ))

    # Embedded URLs
    url_count = features.get("url_count", 0)
    details.append(FeatureDetail(
        name="Embedded Links",
        value=url_count,
        risk_contribution="low" if url_count <= 2 else "medium",
        description=f"Email contains {url_count} link(s)",
    ))

    # IP URLs
    if features.get("has_ip_urls"):
        details.append(FeatureDetail(
            name="IP-Based Links",
            value=True,
            risk_contribution="high",
            description="Email contains links using raw IP addresses",
        ))

    # Free email sender
    if features.get("is_freemail_sender"):
        details.append(FeatureDetail(
            name="Free Email Sender",
            value=features.get("sender_domain", ""),
            risk_contribution="medium",
            description="Sent from a free email provider — legitimate organizations use custom domains",
        ))

    # Hidden content
    if features.get("has_hidden_text"):
        details.append(FeatureDetail(
            name="Hidden Content",
            value=True,
            risk_contribution="high",
            description="Email contains hidden text or elements — a common phishing technique",
        ))

    # Forms
    if features.get("has_form"):
        details.append(FeatureDetail(
            name="Embedded Form",
            value=True,
            risk_contribution="high",
            description="Email contains an embedded form — legitimate emails rarely include forms",
        ))

    return details
