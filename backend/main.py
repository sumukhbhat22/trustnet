"""
Main FastAPI application for TrustNet AI Guardian ML Backend
Provides endpoints for anomaly detection, risk scoring, and network analysis
"""
import sys
import os
from pathlib import Path

# Set up path
backend_path = str(Path(__file__).parent)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from fastapi import FastAPI, APIRouter, HTTPException, Body, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
from datetime import datetime
import json
import asyncio
from models.optimized_models import anomaly_detector, risk_scorer, propagation_analyzer
from models.threat_classifier import threat_classifier
import attack_chain as attack_chain_module
from models.login_detector import (
    geoip_lookup, haversine, hash_fingerprint, compare_fingerprints,
    build_feature_vector, get_or_create_baseline, reset_baseline,
    reset_all_baselines, user_baselines,
)
from models.explainability import build_full_explanation, explain_risk_score, explain_propagation
from routes.schemas import (
    RiskScoreRequest, RiskScoreResponse, AnomalyDetectionRequest,
    PropagationAnalysisRequest, HealthResponse
)

# ── WebSocket connection manager (for instant dashboard push) ──
class ConnectionManager:
    """Manages WebSocket connections for live push to all dashboards."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.append(ws)
        print(f"🔌 Dashboard connected via WebSocket ({len(self.active_connections)} total)")

    def disconnect(self, ws: WebSocket):
        self.active_connections.remove(ws)
        print(f"🔌 Dashboard disconnected ({len(self.active_connections)} remaining)")

    async def broadcast(self, data: dict):
        """Push a threat event to ALL connected dashboards instantly."""
        message = json.dumps(data)
        dead = []
        for conn in self.active_connections:
            try:
                await conn.send_text(message)
            except Exception:
                dead.append(conn)
        for d in dead:
            self.active_connections.remove(d)

    # Alias used throughout the codebase
    async def broadcast_to_admins(self, data: dict):
        await self.broadcast(data)

ws_manager = ConnectionManager()

# ── In-memory live threat feed (updated by attack simulator, polled by frontend)
live_threat_state = {
    "active": False,
    "phase": "idle",           # idle | recon | escalation | breach | exfiltration
    "risk_score": 0,
    "threat_level": "safe",
    "attacker_ip": None,
    "attacker_location": None,
    "attacker_device": None,
    "target_user": None,
    "anomalies": [],
    "ml_result": {},
    "incident": None,
    "compromised_nodes": [],
    "timestamp": None,
}

def reset_live_threat():
    global live_threat_state
    live_threat_state = {
        "active": False,
        "phase": "idle",
        "risk_score": 0,
        "threat_level": "safe",
        "attacker_ip": None,
        "attacker_location": None,
        "attacker_device": None,
        "target_user": None,
        "anomalies": [],
        "ml_result": {},
        "incident": None,
        "compromised_nodes": [],
        "timestamp": None,
    }

# Create FastAPI app
app = FastAPI(
    title="TrustNet AI Guardian ML Backend",
    description="Advanced ML-powered security threat detection and analysis",
    version="1.0.0"
)

# Add CORS middleware with explicit configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Create router
router = APIRouter(prefix="/api", tags=["ml"])

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "message": "TrustNet ML Backend is running",
        "version": "1.0.0"
    }

@router.post("/risk-score", response_model=RiskScoreResponse)
async def calculate_risk_score(request: RiskScoreRequest):
    """
    Calculate risk score for a user using optimized ML model
    
    Enhanced with:
    - Adaptive sensitivity
    - Confidence scoring
    - Multi-factor analysis
    """
    try:
        metrics_dict = request.behavior_metrics.model_dump()
        
        # Use optimized risk scorer with adaptive sensitivity
        result = risk_scorer.calculate_risk_score(
            behavior_metrics=metrics_dict,
            anomaly_score=request.anomaly_score,
            sensitivity=1.0  # Can be adjusted per user
        )
        
        return {
            "overall_score": result['overall_score'],
            "threat_level": result['threat_level'],
            "deviations": result['deviations'],
            "recommendation": result['recommendation']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calculating risk score: {str(e)}")

@router.post("/anomaly-detection")
async def detect_anomalies(request: AnomalyDetectionRequest):
    """
    Detect anomalies using optimized Isolation Forest
    
    Features:
    - RobustScaler preprocessing
    - Optimal contamination parameter
    - Cross-validated hyperparameters
    """
    try:
        if not request.records:
            return {"results": []}
        
        features = list(request.records[0].keys())
        data = np.array([
            [record.get(feature, 0.0) for feature in features]
            for record in request.records
        ])
        
        # Use optimized prediction
        predictions, scores = anomaly_detector.predict(data)
        
        results = []
        for i, record in enumerate(request.records):
            is_anomaly = predictions[i] == -1
            anomaly_score = float(scores[i])
            
            # Better risk level classification
            if anomaly_score > 0.85:
                risk_level = "critical"
            elif anomaly_score > 0.65:
                risk_level = "high"
            elif anomaly_score > 0.4:
                risk_level = "medium"
            elif anomaly_score > 0.15:
                risk_level = "low"
            else:
                risk_level = "safe"
            
            results.append({
                **record,
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(anomaly_score, 4),
                "risk_level": risk_level
            })
        
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error detecting anomalies: {str(e)}")

@router.post("/propagation-analysis")
async def analyze_propagation(request: PropagationAnalysisRequest):
    """Analyze risk propagation through network"""
    try:
        nodes = [
            {
                "id": node.id,
                "label": node.label,
                "type": node.node_type,
                "x": node.x,
                "y": node.y,
                "compromised": node.compromised,
                "propagationRisk": node.propagationRisk
            }
            for node in request.nodes
        ]
        
        edges = [
            {
                "from": edge.from_node,
                "to": edge.to_node,
                "active": edge.active,
                "attackPath": edge.attackPath
            }
            for edge in request.edges
        ]
        
        analysis_result = propagation_analyzer.analyze_network(nodes, edges)
        
        return {
            "total_network_risk": analysis_result['total_network_risk'],
            "critical_count": len(analysis_result['critical_nodes']),
            "critical_nodes": analysis_result['critical_nodes'],
            "all_nodes": analysis_result['all_nodes']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing propagation: {str(e)}")

@router.post("/batch-risk-analysis")
async def batch_risk_analysis(users_data: list = Body(...)):
    """Analyze risk scores for multiple users"""
    try:
        results = []
        for user in users_data:
            user_id = user.get("id")
            metrics = {
                "normal_login_time": user.get("normal_login_time", 9.2),
                "actual_login_time": user.get("actual_login_time", 9.2),
                "normal_session_duration": user.get("normal_session_duration", 4.5),
                "actual_session_duration": user.get("actual_session_duration", 4.5),
                "normal_data_volume": user.get("normal_data_volume", 120),
                "actual_data_volume": user.get("actual_data_volume", 120),
                "normal_api_calls": user.get("normal_api_calls", 45),
                "actual_api_calls": user.get("actual_api_calls", 45),
                "normal_geo_distance": user.get("normal_geo_distance", 0),
                "actual_geo_distance": user.get("actual_geo_distance", 0),
            }
            anomaly_score = user.get("anomaly_score", 0.0)
            risk_analysis = risk_scorer.calculate_risk_score(metrics, anomaly_score)
            
            results.append({
                "user_id": user_id,
                "overall_score": risk_analysis['overall_score'],
                "threat_level": risk_analysis['threat_level'],
                "recommendation": risk_analysis['recommendation'],
                "deviations": risk_analysis['deviations']
            })
        
        return {"user_risk_scores": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in batch analysis: {str(e)}")

# ── Live Threat Endpoints (for real-time demo) ──

@router.get("/live-threat")
async def get_live_threat():
    """Frontend polls this every 2s to get current threat state"""
    return live_threat_state

@router.post("/live-threat/reset")
async def reset_threat():
    """Reset the live threat state"""
    reset_live_threat()
    return {"status": "reset", "message": "Live threat cleared"}

@router.post("/inject-threat")
async def inject_threat(payload: dict = Body(...)):
    """
    Attack simulator sends threat data here.
    The data goes through the REAL ML pipeline before updating the live feed.
    
    Expected payload:
    {
        "phase": "recon|escalation|breach|exfiltration",
        "attacker_ip": "203.0.113.42",
        "attacker_location": "Moscow, RU",
        "attacker_device": "Unknown Linux Host",
        "target_user": "Alex Chen",
        "behavior_metrics": { ... },
        "anomaly_score": 0.0-1.0,
        "anomalies": ["list of anomaly descriptions"],
        "compromised_nodes": ["n1", "n4"]
    }
    """
    global live_threat_state
    
    try:
        # ── Run through REAL ML models ──
        metrics = payload.get("behavior_metrics", {})
        anomaly_score = payload.get("anomaly_score", 0.0)
        
        # 1. Risk scoring via ML
        ml_result = risk_scorer.calculate_risk_score(
            behavior_metrics=metrics,
            anomaly_score=anomaly_score,
            sensitivity=1.0
        )
        
        # 2. Anomaly detection via Isolation Forest
        anomaly_data = np.array([[
            metrics.get("actual_session_duration", 4.5),
            metrics.get("actual_data_volume", 120),
            metrics.get("actual_api_calls", 45),
            metrics.get("actual_geo_distance", 0),
            metrics.get("actual_login_time", 9.2),
        ]])
        predictions, scores = anomaly_detector.predict(anomaly_data)
        
        ml_result["isolation_forest_anomaly"] = bool(predictions[0] == -1)
        ml_result["isolation_forest_score"] = round(float(scores[0]), 4)
        
        # Build incident if risk is medium+
        incident = None
        if ml_result["overall_score"] >= 25:
            incident = {
                "id": f"INC-{int(datetime.now().timestamp())}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "userId": "u1",
                "userName": payload.get("target_user", "Unknown"),
                "type": payload.get("attack_type", "Suspicious Activity"),
                "description": payload.get("description", "Anomalous behavior detected by ML pipeline"),
                "riskScore": round(ml_result["overall_score"]),
                "threatLevel": ml_result["threat_level"],
                "status": "active",
                "response": ml_result["recommendation"],
                "deviation": round(max(ml_result["deviations"].values())),
            }
        
        # Update the live state
        live_threat_state = {
            "active": True,
            "phase": payload.get("phase", "recon"),
            "risk_score": round(ml_result["overall_score"]),
            "threat_level": ml_result["threat_level"],
            "attacker_ip": payload.get("attacker_ip"),
            "attacker_location": payload.get("attacker_location"),
            "attacker_device": payload.get("attacker_device"),
            "target_user": payload.get("target_user"),
            "anomalies": payload.get("anomalies", []),
            "ml_result": ml_result,
            "incident": incident,
            "compromised_nodes": payload.get("compromised_nodes", []),
            "timestamp": datetime.now().isoformat(),
        }
        
        phase = payload.get("phase", "?")
        score = ml_result["overall_score"]
        level = ml_result["threat_level"]
        print(f"🔴 LIVE THREAT [{phase.upper()}] → Score: {score} | Level: {level} | IF-Anomaly: {ml_result['isolation_forest_anomaly']}")
        
        return {
            "status": "injected",
            "ml_result": ml_result,
            "live_threat": live_threat_state
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat injection failed: {str(e)}")

# ── WebSocket endpoint (ADMIN dashboards connect here — attackers never see this) ──
@app.websocket("/ws/admin")
async def admin_websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ── Real Login Detection Endpoint ──
@router.post("/login")
async def real_login(request: Request, payload: dict = Body(...)):
    """
    REAL login detection pipeline:
      1. Receive device fingerprint from browser
      2. Get client IP → GeoIP lookup → lat/lon
      3. Compare fingerprint against stored baseline
      4. Calculate haversine geo distance
      5. Build ML feature vector from REAL data
      6. Run through Isolation Forest + Risk Scorer
      7. Push result to dashboard via WebSocket

    Expected payload from frontend:
    {
        "username": "alex_chen",
        "fingerprint": { userAgent, platform, screenResolution, timezone, ... }
    }
    """
    global live_threat_state

    username = payload.get("username", "unknown")
    password = payload.get("password", "")
    fingerprint = payload.get("fingerprint", {})
    source_fingerprint_id = payload.get("fingerprint_id", "")

    # ── STEP 0: Password validation ──
    valid_credentials = {
        "sumukh": "sumukh@123",
        "alex_chen": "admin123",
        "admin": "admin123",
    }
    expected_pw = valid_credentials.get(username.lower())
    password_valid = expected_pw is not None and password == expected_pw

    if not password_valid:
        # Still get client IP for the alert
        fail_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not fail_ip:
            fail_ip = request.client.host if request.client else "127.0.0.1"

        failed_event = {
            "type": "login_threat",
            "active": True,
            "phase": "login",
            "source_fingerprint_id": source_fingerprint_id,
            "username": username,
            "risk_score": 85,
            "threat_level": "high",
            "attacker_ip": fail_ip,
            "attacker_location": "Unknown",
            "attacker_device": f"{fingerprint.get('deviceType', 'unknown')} — {fingerprint.get('platform', 'unknown')}",
            "target_user": username,
            "attack_type": "Failed Login — Invalid Credentials",
            "anomalies": ["Invalid password attempt", f"Username: {username}", f"Source IP: {fail_ip}"],
            "compromised_nodes": ["n1"],
            "incident": {
                "id": f"INC-{int(datetime.now().timestamp())}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "userId": "u1",
                "userName": username,
                "type": "Failed Login — Invalid Credentials",
                "description": f"Invalid password attempt for user '{username}' from {fail_ip}",
                "riskScore": 85,
                "threatLevel": "high",
                "status": "active",
                "response": "Block source IP",
                "deviation": 100,
            },
            "timestamp": datetime.now().isoformat(),
        }

        # Update live_threat_state so polling also keeps the threat active
        live_threat_state = {
            **failed_event,
            "type": "login_threat",
        }

        # Push failed login to admin dashboards
        await ws_manager.broadcast_to_admins(failed_event)
        print(f"\n{'─'*60}")
        print(f"🚨 FAILED LOGIN: {username} (wrong password) from {fail_ip}")
        print(f"{'─'*60}")

        return {
            **failed_event,
            "login_status": "denied",
            "message": "Invalid username or password.",
        }

    # ── STEP 2: Get real client IP & geolocation ──
    # X-Forwarded-For handles proxies / ngrok
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "127.0.0.1"

    geo = await geoip_lookup(client_ip)
    login_hour = datetime.now().hour

    print(f"\n{'─'*60}")
    print(f"🔐 LOGIN ATTEMPT: {username}")
    print(f"   IP: {client_ip}")
    print(f"   Geo: {geo['city']}, {geo['country']} ({geo['lat']}, {geo['lon']})")
    print(f"   Device: {fingerprint.get('deviceType', '?')} | {fingerprint.get('platform', '?')}")
    print(f"   Screen: {fingerprint.get('screenResolution', '?')} | Canvas: {fingerprint.get('canvasHash', '?')}")
    print(f"   Time: {login_hour}:00")

    # ── STEP 3: Compare with stored baseline ──
    baseline = get_or_create_baseline(username, fingerprint, geo, login_hour)
    is_first_login = (baseline["created_at"] == baseline.get("created_at"))

    # Fingerprint comparison
    fp_comparison = compare_fingerprints(baseline["fingerprint"], fingerprint)

    # Geo distance (haversine)
    baseline_geo = baseline["geo"]
    geo_distance = haversine(
        baseline_geo["lat"], baseline_geo["lon"],
        geo["lat"], geo["lon"]
    )

    # Login hour deviation
    hour_deviation = abs(login_hour - baseline.get("normal_login_hour", 9))

    print(f"\n   📊 COMPARISON vs BASELINE:")
    print(f"   Device match:  {fp_comparison['match_score']*100:.0f}% ({fp_comparison['fields_matched']}/{fp_comparison['fields_total']} fields)")
    print(f"   Same device:   {'YES ✅' if fp_comparison['is_same_device'] else 'NO ⚠ MISMATCH'}")
    print(f"   Geo distance:  {geo_distance:.0f} km")
    print(f"   Hour deviation: {hour_deviation}h")

    if fp_comparison["differences"]:
        print(f"   Changes:")
        for d in fp_comparison["differences"][:5]:
            print(f"     → {d}")

    # ── STEP 4: Build ML feature vector from REAL data ──
    features = build_feature_vector(
        login_hour=login_hour,
        geo_distance_km=geo_distance,
        device_match_score=fp_comparison["match_score"],
        baseline=baseline,
    )

    # ── STEP 5: Run through REAL ML models ──
    metrics = features["behavior_metrics"]
    anomaly_score_input = features["anomaly_score"]

    # Risk Scorer
    ml_result = risk_scorer.calculate_risk_score(
        behavior_metrics=metrics,
        anomaly_score=anomaly_score_input,
        sensitivity=1.0,
    )

    # Isolation Forest
    anomaly_data = np.array([[
        metrics["actual_session_duration"],
        metrics["actual_data_volume"],
        metrics["actual_api_calls"],
        metrics["actual_geo_distance"],
        metrics["actual_login_time"],
    ]])
    predictions, scores = anomaly_detector.predict(anomaly_data)
    ml_result["isolation_forest_anomaly"] = bool(predictions[0] == -1)
    ml_result["isolation_forest_score"] = round(float(scores[0]), 4)

    risk_score = round(ml_result["overall_score"])
    threat_level = ml_result["threat_level"]

    # ── STEP 5b: Supervised Threat Classifier ──
    # Build deviations for classifier features
    session_dev = ml_result.get("deviations", {}).get("session_duration", 0)
    data_dev = ml_result.get("deviations", {}).get("data_volume", 0)
    api_dev = ml_result.get("deviations", {}).get("api_calls", 0)

    prediction = threat_classifier.predict(
        login_hour_deviation=float(hour_deviation),
        geo_distance_km=float(geo_distance),
        device_match_score=float(fp_comparison["match_score"]),
        session_deviation_pct=float(session_dev),
        data_volume_deviation_pct=float(data_dev),
        api_calls_deviation_pct=float(api_dev),
        isolation_forest_score=float(ml_result.get("isolation_forest_score", 0)),
    )

    print(f"\n   🧠 ML RESULTS:")
    print(f"   Risk Score:         {risk_score}/100")
    print(f"   Threat Level:       {threat_level.upper()}")
    print(f"   IF Anomaly:         {'YES ⚠' if ml_result['isolation_forest_anomaly'] else 'No'}")
    print(f"   IF Score:           {ml_result['isolation_forest_score']}")
    print(f"   Recommendation:     {ml_result['recommendation']}")
    print(f"   Confidence:         {ml_result.get('confidence', 'N/A')}%")
    print(f"\n   🎯 SUPERVISED PREDICTION:")
    print(f"   Verdict:            {prediction['prediction']}")
    print(f"   Attack Type:        {prediction['attack_label']}")
    print(f"   Confidence:         {prediction['confidence']}%")
    print(f"   Action:             {prediction['action']}")
    print(f"{'─'*60}")

    # Build anomaly descriptions from REAL differences
    anomalies = []
    if not fp_comparison["is_same_device"]:
        anomalies.append(f"New device detected — {100 - fp_comparison['match_score']*100:.0f}% fingerprint mismatch")
    if geo_distance > 100:
        anomalies.append(f"Geo-location deviation: {geo_distance:,.0f} km ({geo['city']}, {geo['country']})")
    if hour_deviation > 4:
        anomalies.append(f"Login time deviation: {login_hour}:00 (normal: {baseline.get('normal_login_hour', 9)}:00)")
    if ml_result["isolation_forest_anomaly"]:
        anomalies.append(f"Isolation Forest flagged as anomaly (score: {ml_result['isolation_forest_score']})")
    for key, val in ml_result.get("deviations", {}).items():
        if val > 80:
            anomalies.append(f"{key}: {val:.0f}% deviation from baseline")

    # Determine compromised nodes based on risk
    compromised = []
    if risk_score > 30:
        compromised.append("n1")  # User endpoint
    if risk_score > 50:
        compromised.append("n4")  # Web app
    if risk_score > 70:
        compromised.extend(["n7", "n9"])  # Core server + DB

    # ── STEP 5c: Explainable AI ──
    explanation = build_full_explanation(
        baseline_fp=baseline["fingerprint"],
        current_fp=fingerprint,
        match_score=fp_comparison["match_score"],
        is_same_device=fp_comparison["is_same_device"],
        features_used=prediction.get("features_used", {}),
        prediction=prediction,
        rf_model=threat_classifier.rf_model,
        gb_model=threat_classifier.gb_model,
        scaler=threat_classifier.scaler,
        ml_result=ml_result,
        geo_distance_km=geo_distance,
        device_match_score=fp_comparison["match_score"],
        isolation_forest_score=ml_result.get("isolation_forest_score", 0),
        isolation_forest_anomaly=ml_result.get("isolation_forest_anomaly", False),
        compromised_nodes=compromised,
        risk_score=risk_score,
    )
    print(f"   🧩 XAI: {len(explanation)} explanation layers generated")

    # Build incident
    incident = None
    if risk_score >= 25:
        incident = {
            "id": f"INC-{int(datetime.now().timestamp())}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "userId": "u1",
            "userName": username,
            "type": "Real Login — " + ("New Device" if not fp_comparison["is_same_device"] else "Geo Anomaly"),
            "description": "; ".join(anomalies[:3]) if anomalies else "Anomalous login detected",
            "riskScore": risk_score,
            "threatLevel": threat_level,
            "status": "active",
            "response": ml_result["recommendation"],
            "deviation": round(max(ml_result["deviations"].values())) if ml_result.get("deviations") else 0,
        }

    # ── STEP 6 & 7: Update live state + push via WebSocket ──
    threat_event = {
        "type": "login_threat",
        "active": True,
        "phase": "login",
        "source_fingerprint_id": source_fingerprint_id,
        "username": username,
        "risk_score": max(risk_score, 30) if not fp_comparison["is_same_device"] else risk_score,
        "threat_level": threat_level,
        "attacker_ip": client_ip,
        "attacker_location": f"{geo['city']}, {geo['country']}",
        "attacker_device": f"{fingerprint.get('deviceType', 'unknown')} — {fingerprint.get('platform', 'unknown')}",
        "target_user": username,
        "attack_type": prediction["attack_label"] if prediction["is_malicious"] else "Real Login Detection",
        "prediction": prediction,
        "anomalies": anomalies,
        "ml_result": ml_result,
        "fingerprint_comparison": fp_comparison,
        "geo_distance_km": round(geo_distance, 1),
        "geo": geo,
        "login_hour": login_hour,
        "incident": incident,
        "compromised_nodes": compromised,
        "explanation": explanation,
        "timestamp": datetime.now().isoformat(),
    }

    # Update the polled live_threat_state too (for backward compat)
    live_threat_state = {
        "active": True,
        "phase": "login",
        "source_fingerprint_id": source_fingerprint_id,
        "risk_score": max(risk_score, 30) if not fp_comparison["is_same_device"] else risk_score,
        "threat_level": threat_level,
        "attacker_ip": client_ip,
        "attacker_location": f"{geo['city']}, {geo['country']}",
        "attacker_device": f"{fingerprint.get('deviceType', 'unknown')} — {fingerprint.get('platform', 'unknown')}",
        "target_user": username,
        "anomalies": anomalies,
        "ml_result": ml_result,
        "prediction": prediction,
        "fingerprint_comparison": fp_comparison,
        "geo_distance_km": round(geo_distance, 1),
        "geo": geo,
        "login_hour": login_hour,
        "incident": incident,
        "compromised_nodes": compromised,
        "explanation": explanation,
        "timestamp": datetime.now().isoformat(),
    }

    # Push to admin dashboards via WebSocket
    await ws_manager.broadcast_to_admins(threat_event)

    # Add simplified login_status for the attacker-facing login portal
    # Key rule: if device fingerprint doesn't match → ACCESS DENIED
    if not fp_comparison["is_same_device"]:
        login_status = "denied"
        user_message = "Access denied. Unrecognized device."
    elif risk_score >= 70:
        login_status = "restricted"
        user_message = "Access temporarily restricted. Please contact your administrator."
    else:
        login_status = "allowed"
        user_message = "Login successful."

    # Return full data (admin dashboard reads ML fields) + simplified fields (login portal reads login_status)
    return {
        **threat_event,
        "login_status": login_status,
        "message": user_message,
    }


@router.get("/baselines")
async def get_baselines():
    """Get all stored user baselines (for admin view)."""
    result = {}
    for username, b in user_baselines.items():
        result[username] = {
            "fingerprint_hash": b.get("fingerprint_hash"),
            "device_type": b.get("fingerprint", {}).get("deviceType"),
            "location": f"{b['geo']['city']}, {b['geo']['country']}",
            "normal_login_hour": b.get("normal_login_hour"),
            "created_at": b.get("created_at"),
        }
    return {"baselines": result, "count": len(result)}


@router.post("/baselines/reset")
async def reset_baselines_endpoint(payload: dict = Body(default={})):
    """Reset baselines. Optionally pass {"username": "..."} for single user."""
    username = payload.get("username")
    if username:
        ok = reset_baseline(username)
        return {"status": "reset" if ok else "not_found", "username": username}
    reset_all_baselines()
    return {"status": "all_cleared"}


# ── Attack Chain Simulation Endpoints ──

@router.post("/attack-chain/start")
async def start_attack_chain():
    """Start the 6-phase simulated attack chain."""
    global live_threat_state
    if attack_chain_module.is_running():
        return {"status": "already_running"}

    def update_live(event: dict):
        global live_threat_state
        live_threat_state = event

    asyncio.create_task(
        attack_chain_module.run_attack_chain(
            broadcast_fn=ws_manager.broadcast_to_admins,
            update_live_state=update_live,
        )
    )
    return {"status": "started", "phases": 6, "total_steps": sum(len(p['steps']) for p in attack_chain_module.PHASES)}


@router.post("/attack-chain/stop")
async def stop_attack_chain():
    """Stop the running attack chain."""
    attack_chain_module.stop()
    reset_live_threat()
    await ws_manager.broadcast_to_admins({"type": "attack_chain_stopped", "active": False})
    return {"status": "stopped"}


@router.get("/attack-chain/status")
async def attack_chain_status():
    """Check if attack chain is currently running."""
    return {"running": attack_chain_module.is_running()}


# Include router
app.include_router(router)

@app.on_event("startup")
async def startup_event():
    """Initialize and train optimized models on startup"""
    print("\n" + "="*70)
    print("🚀 TrustNet ML Backend Starting Up")
    print("="*70)
    
    try:
        # Train the optimized anomaly detector
        print("\n📊 Training Isolation Forest with optimal parameters...")
        result = anomaly_detector.train()
        
        if result['status'] == 'success':
            print(f"✅ Anomaly Detector Ready!")
            print(f"   - Precision: {result['metrics'].get('precision', 'N/A')}")
            print(f"   - Recall: {result['metrics'].get('recall', 'N/A')}")
            print(f"   - F1-Score: {result['metrics'].get('f1', 'N/A')}")
            print(f"   - Best Contamination: {result['best_params'].get('contamination')}")
            print(f"   - N-Estimators: {result['best_params'].get('n_estimators')}")
        else:
            print(f"⚠️  Warning: {result['message']}")
        
        print(f"\n✅ Risk Scorer initialized with optimal weights")
        print(f"✅ Propagation Analyzer initialized")

        # Train the supervised threat classifier
        print("\n" + "-"*60)
        tc_result = threat_classifier.train()
        if tc_result["status"] == "success":
            m = tc_result["metrics"]
            print(f"\n✅ Threat Classifier Ready!")
            print(f"   - Ensemble Accuracy: {m['accuracy']}")
            print(f"   - F1 (weighted):     {m['f1_weighted']}")
            print(f"   - 5-Fold CV F1:      {m['cv_f1_mean']} ± {m['cv_f1_std']}")
        print("-"*60)

        print("\n" + "="*70)
        print("🎯 TrustNet ML Backend Ready - All Models Trained")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"⚠️  Startup warning: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("TrustNet ML Backend shutting down...")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "TrustNet AI Guardian ML Backend",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "openapi": "/openapi.json"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
