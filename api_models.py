from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import lightgbm as lgb
import numpy as np
import uvicorn
from datetime import datetime, timedelta
from collections import defaultdict, deque
import re
import hashlib
import json
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Advanced AI-Powered API Gateway", version="2.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ENUMS AND DATA CLASSES
class ThreatLevel(Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"

class AttackType(Enum):
    NONE = "NONE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    DDOS = "DDOS"
    BRUTE_FORCE = "BRUTE_FORCE"
    API_ABUSE = "API_ABUSE"

@dataclass
class ThreatAnalysisResult:
    is_malicious: bool
    threat_level: str
    threat_score: float
    attack_type: str
    ip_reputation: float
    rate_limited: bool
    confidence: float
    recommended_action: str
    feature_importance: Dict[str, float]
    explanation: str
    timestamp: str


class Config:
    # Reputation system (MORE AGGRESSIVE)
    DECAY_RATE = 0.95
    REPUTATION_THRESHOLD_BLOCK = -30  # Lowered from -50
    REPUTATION_THRESHOLD_THROTTLE = -15  # Lowered from -20
    
    # Rate limiting (STRICTER)
    RATE_LIMIT_WINDOW = 60
    MAX_REQUESTS_PER_WINDOW = 80  # Lowered from 100
    DDOS_THRESHOLD = 150  # Lowered from 200
    
    # Model thresholds (MORE SENSITIVE)
    ISO_CONTAMINATION = 0.15
    LGB_THRESHOLD_HIGH = 0.65  # Lowered from 0.7
    LGB_THRESHOLD_MEDIUM = 0.45  # Lowered from 0.5
    
    # Adaptive thresholds
    ADAPTIVE_THRESHOLD_ENABLED = True
    FALSE_POSITIVE_WINDOW = 3600
    
    # Sequential analysis
    SEQUENCE_WINDOW = 10
    PATTERN_MEMORY_SIZE = 1000

config = Config()

# ENHANCED IP REPUTATION SYSTEM

class EnhancedIPReputationSystem:
    def __init__(self):
        self.reputation: Dict[str, float] = defaultdict(float)
        self.last_update: Dict[str, datetime] = {}
        self.request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.request_history: Dict[str, List[Dict]] = defaultdict(list)
        self.blocked_ips: Dict[str, datetime] = {}
        self.throttled_ips: Dict[str, float] = {}
        self.whitelist: set = set()
        
        # Behavioral tracking
        self.failed_auth_count: Dict[str, int] = defaultdict(int)
        self.endpoint_diversity: Dict[str, set] = defaultdict(set)
        self.user_agent_changes: Dict[str, List[str]] = defaultdict(list)
        
    def apply_decay(self, ip: str):
        """Apply time-based decay to IP reputation"""
        if ip in self.last_update:
            time_diff = (datetime.now() - self.last_update[ip]).total_seconds() / 3600
            decay_factor = config.DECAY_RATE ** time_diff
            self.reputation[ip] *= decay_factor
        self.last_update[ip] = datetime.now()
    
    def update_reputation(self, ip: str, score_delta: float, reason: str = ""):
        """Update IP reputation with reason logging"""
        self.apply_decay(ip)
        old_score = self.reputation[ip]
        self.reputation[ip] += score_delta
        
        logger.info(f"IP {ip} reputation: {old_score:.2f} -> {self.reputation[ip]:.2f} ({reason})")
        
        # Auto-block/throttle based on reputation
        if self.reputation[ip] < config.REPUTATION_THRESHOLD_BLOCK:
            self.block_ip(ip, "Low reputation score")
        elif self.reputation[ip] < config.REPUTATION_THRESHOLD_THROTTLE:
            self.throttle_ip(ip, 0.5)  # 50% throttle
    
    def get_reputation(self, ip: str) -> float:
        """Get current reputation with decay applied"""
        if ip in self.whitelist:
            return 100.0
        self.apply_decay(ip)
        return self.reputation[ip]
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, int]:
        """Check if IP exceeds rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=config.RATE_LIMIT_WINDOW)
        
        # Clean old requests
        while self.request_counts[ip] and self.request_counts[ip][0] < cutoff:
            self.request_counts[ip].popleft()
        
        # Add current request
        self.request_counts[ip].append(now)
        count = len(self.request_counts[ip])
        
        # Check for DDoS patterns
        is_ddos = count > config.DDOS_THRESHOLD
        is_rate_limited = count > config.MAX_REQUESTS_PER_WINDOW
        
        return is_rate_limited or is_ddos, count
    
    def block_ip(self, ip: str, reason: str):
        """Block an IP address"""
        self.blocked_ips[ip] = datetime.now()
        logger.warning(f"🚫 Blocked IP {ip}: {reason}")
    
    def throttle_ip(self, ip: str, factor: float):
        """Throttle an IP address"""
        self.throttled_ips[ip] = factor
        logger.info(f"⚠️ Throttled IP {ip}: {factor*100}%")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        if ip in self.whitelist:
            return False
        
        if ip in self.blocked_ips:
            # Auto-unblock after 24 hours
            if (datetime.now() - self.blocked_ips[ip]).total_seconds() > 86400:
                del self.blocked_ips[ip]
                self.reputation[ip] = 0  # Reset reputation
                return False
            return True
        return False
    
    def get_throttle_factor(self, ip: str) -> float:
        """Get throttle factor for IP"""
        return self.throttled_ips.get(ip, 1.0)
    
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        self.whitelist.add(ip)
        logger.info(f"✅ Added {ip} to whitelist")
    
    def track_behavior(self, ip: str, endpoint: str, user_agent: str, failed_auth: bool = False):
        """Track behavioral patterns"""
        self.endpoint_diversity[ip].add(endpoint)
        
        if user_agent and user_agent not in self.user_agent_changes[ip]:
            self.user_agent_changes[ip].append(user_agent)
            if len(self.user_agent_changes[ip]) > 5:  # Suspicious UA switching
                self.update_reputation(ip, -5, "Frequent User-Agent changes")
        
        if failed_auth:
            self.failed_auth_count[ip] += 1
            if self.failed_auth_count[ip] > 5:
                self.update_reputation(ip, -15, "Multiple failed authentications")

ip_reputation = EnhancedIPReputationSystem()

# ENHANCED ATTACK PATTERN DETECTION
class EnhancedAttackPatterns:
    """Advanced pattern detection with scoring"""
    
    PATTERNS = {
        AttackType.SQL_INJECTION: [
            (r"(\bunion\b.*\bselect\b)", 20),
            (r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", 25),
            (r"(;\s*drop\s+table)", 30),
            (r"(exec\s*\()", 20),
            (r"(xp_cmdshell)", 30),
            (r"(\/\*.*\*\/)", 10),
            (r"(--\s)", 10),
        ],
        AttackType.XSS: [
            (r"<script[^>]*>.*?</script>", 25),
            (r"javascript:", 20),
            (r"onerror\s*=", 20),
            (r"onload\s*=", 20),
            (r"<iframe", 25),
            (r"eval\s*\(", 20),
            (r"document\.cookie", 15),
        ],
        AttackType.PATH_TRAVERSAL: [
            (r"\.\./", 20),
            (r"\.\.\\", 20),
            (r"%2e%2e", 25),
            (r"\.\.%2f", 25),
            (r"/etc/passwd", 30),
            (r"c:\\windows", 30),
        ],
        AttackType.COMMAND_INJECTION: [
            (r";\s*cat\s+", 25),
            (r";\s*ls\s+", 20),
            (r"\|\s*cat\s+", 25),
            (r"&&\s*", 15),
            (r"`.*`", 20),
            (r"\$\(.*\)", 20),
        ],
    }
    
    @classmethod
    def detect_attack_type(cls, text: str) -> Tuple[AttackType, int, List[str]]:
        """Detect attack type with confidence score and matched patterns"""
        text = text.lower()
        max_score = 0
        detected_type = AttackType.NONE
        matched_patterns = []
        
        for attack_type, patterns in cls.PATTERNS.items():
            score = 0
            matches = []
            for pattern, weight in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    score += weight
                    matches.append(pattern)
            
            if score > max_score:
                max_score = score
                detected_type = attack_type
                matched_patterns = matches
        
        return detected_type, max_score, matched_patterns

# =============================================================================
# ADVANCED FEATURE EXTRACTION
# =============================================================================
class AdvancedFeatureExtractor:
    """Extract 25+ features for ML models"""
    
    FEATURE_NAMES = [
        "method_encoded", "path_length", "body_length", "digit_count",
        "header_count", "missing_user_agent", "quote_count", "html_tag_count",
        "traversal_patterns", "sql_keywords", "ip_reputation", "request_rate",
        "entropy_body", "entropy_path", "special_char_count", "length_ratio",
        "endpoint_diversity", "user_agent_changes", "failed_auth_ratio",
        "time_of_day", "is_weekend", "payload_entropy", "header_anomaly_score",
        "request_interval_variance", "suspicious_param_count"
    ]
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        entropy = 0
        for c in set(text):
            p = text.count(c) / len(text)
            entropy -= p * np.log2(p + 1e-10)
        return entropy
    
    @staticmethod
    def extract_features(request_data: dict, ip: str, history: List[Dict]) -> np.ndarray:
        """Extract comprehensive feature vector"""
        method = request_data.get("method", "GET")
        path = request_data.get("path", "/")
        body = request_data.get("body", "")
        headers = request_data.get("headers", {})
        
        # Basic features
        method_map = {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4, "PATCH": 5}
        f1 = method_map.get(method, 0)
        f2 = len(path)
        f3 = len(body)
        f4 = sum(1 for c in body if c.isdigit())
        
        # Header analysis
        f5 = len(headers)
        f6 = 1 if "user-agent" not in str(headers).lower() else 0
        
        # Pattern counts
        f7 = body.count("'") + body.count('"')
        f8 = body.count("<") + body.count(">")
        f9 = body.count("..") + path.count("..")
        f10 = len(re.findall(r"union|select|drop|exec|script", body + path, re.I))
        
        # Reputation and rate
        f11 = ip_reputation.get_reputation(ip)
        f12 = len(ip_reputation.request_counts.get(ip, []))
        
        # Entropy measures
        f13 = AdvancedFeatureExtractor.calculate_entropy(body)
        f14 = AdvancedFeatureExtractor.calculate_entropy(path)
        
        # Special characters
        f15 = sum(1 for c in body + path if not c.isalnum() and c not in "/?&=.-_")
        
        # Ratios
        f16 = len(body) / max(len(path), 1)
        
        # Behavioral features
        f17 = len(ip_reputation.endpoint_diversity.get(ip, set()))
        f18 = len(ip_reputation.user_agent_changes.get(ip, []))
        f19 = ip_reputation.failed_auth_count.get(ip, 0) / max(f12, 1)
        
        # Temporal features
        now = datetime.now()
        f20 = now.hour  # Time of day
        f21 = 1 if now.weekday() >= 5 else 0  # Weekend
        
        # Advanced features
        f22 = AdvancedFeatureExtractor.calculate_entropy(json.dumps(headers))
        
        # Header anomaly score
        expected_headers = {"user-agent", "accept", "host"}
        present_headers = set(k.lower() for k in headers.keys())
        f23 = len(expected_headers - present_headers)
        
        # Request interval variance (if history available)
        if len(history) > 1:
            intervals = []
            for i in range(1, len(history)):
                t1 = datetime.fromisoformat(history[i-1].get("timestamp", datetime.now().isoformat()))
                t2 = datetime.fromisoformat(history[i].get("timestamp", datetime.now().isoformat()))
                intervals.append((t2 - t1).total_seconds())
            f24 = np.var(intervals) if intervals else 0
        else:
            f24 = 0
        
        # Suspicious parameter count
        suspicious_params = ["admin", "root", "password", "passwd", "cmd", "exec"]
        f25 = sum(1 for param in suspicious_params if param in (body + path).lower())
        
        features = [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15,
                   f16, f17, f18, f19, f20, f21, f22, f23, f24, f25]
        
        return np.array(features).reshape(1, -1)

# MODEL TRAINING
def generate_advanced_training_data(n_samples=2000):
    """Generate enhanced synthetic training data"""
    X_benign = []
    X_malicious = []
    
    # Benign samples
    for _ in range(n_samples // 2):
        features = [
            np.random.choice([1, 2]),  # method
            np.random.randint(5, 50),  # path length
            np.random.randint(0, 200),  # body length
            np.random.randint(0, 10),  # digits
            np.random.randint(5, 15),  # headers
            0,  # has UA
            np.random.randint(0, 5),  # quotes
            np.random.randint(0, 3),  # tags
            0,  # traversal
            0,  # sql keywords
            np.random.uniform(-5, 10),  # reputation
            np.random.randint(1, 50),  # request rate
            np.random.uniform(2, 4),  # entropy body
            np.random.uniform(2, 4),  # entropy path
            np.random.randint(0, 10),  # special chars
            np.random.uniform(0, 3),  # length ratio
            np.random.randint(1, 20),  # endpoint diversity
            np.random.randint(0, 2),  # UA changes
            0,  # failed auth ratio
            np.random.randint(0, 24),  # time of day
            np.random.choice([0, 1]),  # weekend
            np.random.uniform(2, 4),  # payload entropy
            np.random.randint(0, 2),  # header anomaly
            np.random.uniform(0, 10),  # interval variance
            0,  # suspicious params
        ]
        X_benign.append(features)
    
    # Malicious samples
    for _ in range(n_samples // 2):
        features = [
            np.random.choice([1, 2]),
            np.random.randint(20, 200),  # longer paths
            np.random.randint(100, 1000),  # longer bodies
            np.random.randint(20, 100),  # many digits
            np.random.randint(0, 10),  # fewer headers
            np.random.choice([0, 1]),  # missing UA
            np.random.randint(10, 50),  # many quotes
            np.random.randint(5, 30),  # many tags
            np.random.randint(0, 10),  # traversal
            np.random.randint(1, 15),  # sql keywords
            np.random.uniform(-50, -10),  # bad reputation
            np.random.randint(100, 300),  # high rate
            np.random.uniform(4, 7),  # high entropy
            np.random.uniform(4, 6),  # high entropy
            np.random.randint(20, 100),  # many special chars
            np.random.uniform(5, 30),  # high ratio
            np.random.randint(1, 5),  # low diversity
            np.random.randint(3, 10),  # many UA changes
            np.random.uniform(0.2, 0.8),  # high failed auth
            np.random.randint(0, 24),
            np.random.choice([0, 1]),
            np.random.uniform(5, 8),  # very high entropy
            np.random.randint(2, 5),  # header anomalies
            np.random.uniform(20, 100),  # high variance
            np.random.randint(2, 10),  # suspicious params
        ]
        X_malicious.append(features)
    
    X = np.array(X_benign + X_malicious)
    y = np.array([0] * len(X_benign) + [1] * len(X_malicious))
    
    return X, y

# Train models
logger.info("🔧 Training advanced AI models...")

# Isolation Forest
logger.info("  └─ Training Isolation Forest...")
X_train_iso, _ = generate_advanced_training_data(2000)
scaler = StandardScaler()
X_train_iso_scaled = scaler.fit_transform(X_train_iso)
iso_model = IsolationForest(
    contamination=config.ISO_CONTAMINATION,
    random_state=42,
    n_estimators=150,
    max_samples='auto',
    bootstrap=True
)
iso_model.fit(X_train_iso_scaled)

# LightGBM
logger.info("  └─ Training LightGBM...")
X_train, y_train = generate_advanced_training_data(2000)
X_train_scaled = scaler.transform(X_train)
lgb_model = lgb.LGBMClassifier(
    n_estimators=150,
    max_depth=7,
    learning_rate=0.05,
    num_leaves=31,
    random_state=42,
    verbose=-1,
    class_weight='balanced'
)
lgb_model.fit(X_train_scaled, y_train)

logger.info("✅ Models trained successfully!")

# =============================================================================
# FEATURE IMPORTANCE & EXPLAINABILITY
# =============================================================================
def get_feature_importance(features: np.ndarray) -> Dict[str, float]:
    """Get feature importance for explainability"""
    feature_importance = lgb_model.feature_importances_
    feature_dict = {}
    
    for i, importance in enumerate(feature_importance):
        if i < len(AdvancedFeatureExtractor.FEATURE_NAMES):
            feature_dict[AdvancedFeatureExtractor.FEATURE_NAMES[i]] = float(importance)
    
    # Sort by importance
    sorted_features = dict(sorted(feature_dict.items(), key=lambda x: x[1], reverse=True)[:5])
    return sorted_features

def generate_explanation(result: dict, matched_patterns: List[str]) -> str:
    """Generate human-readable explanation"""
    explanations = []
    
    if result["attack_type"] != "NONE":
        explanations.append(f"Detected {result['attack_type']} pattern")
        if matched_patterns:
            explanations.append(f"Matched patterns: {', '.join(matched_patterns[:3])}")
    
    if result["isolation_forest_anomaly"]:
        explanations.append("Request exhibits anomalous behavior")
    
    if result["lightgbm_probability"] > 0.7:
        explanations.append(f"ML model confidence: {result['lightgbm_probability']:.1%}")
    
    if result["ip_reputation"] < -20:
        explanations.append(f"Low IP reputation: {result['ip_reputation']:.1f}")
    
    if result["rate_limited"]:
        explanations.append("Rate limit exceeded")
    
    return " | ".join(explanations) if explanations else "Request appears normal"

# ADVANCED THREAT ANALYSIS
async def analyze_threat_advanced(request_data: dict, ip: str) -> ThreatAnalysisResult:
    """Comprehensive threat analysis with explainability"""
    
    # Check if IP is blocked
    if ip_reputation.is_blocked(ip):
        return ThreatAnalysisResult(
            is_malicious=True,
            threat_level=ThreatLevel.CRITICAL.value,
            threat_score=100.0,
            attack_type=AttackType.NONE.value,
            ip_reputation=ip_reputation.get_reputation(ip),
            rate_limited=False,
            confidence=1.0,
            recommended_action="BLOCK",
            feature_importance={},
            explanation="IP is currently blocked",
            timestamp=datetime.now().isoformat()
        )
    
    # Extract features
    history = ip_reputation.request_history.get(ip, [])[-10:]
    features = AdvancedFeatureExtractor.extract_features(request_data, ip, history)
    features_scaled = scaler.transform(features)
    
    # Pattern-based detection
    combined_text = f"{request_data.get('path', '')} {request_data.get('body', '')}"
    attack_type, pattern_score, matched_patterns = EnhancedAttackPatterns.detect_attack_type(combined_text)
    
    # ML predictions
    iso_pred = iso_model.predict(features_scaled)[0]
    iso_score = iso_model.decision_function(features_scaled)[0]
    
    lgb_prob = lgb_model.predict_proba(features_scaled)[0][1]
    
    # Reputation and rate limiting
    reputation = ip_reputation.get_reputation(ip)
    rate_limited, request_count = ip_reputation.check_rate_limit(ip)
    
    # Calculate threat score (0-100)
    threat_score = 0.0
    
    # Anomaly detection contribution (more aggressive)
    if iso_pred == -1:
        threat_score += 35  # Increased from 25
    
    # Classification contribution (more weight)
    threat_score += lgb_prob * 45  # Increased from 35
    
    # Pattern matching contribution (critical attacks get instant high score)
    if pattern_score > 0:
        threat_score += min(pattern_score * 1.5, 40)  # Amplified pattern impact
    
    # Reputation contribution
    if reputation < -30:
        threat_score += 25  # Increased from 20
    elif reputation < -10:
        threat_score += 15  # Increased from 10
    
    # Rate limiting contribution
    if rate_limited:
        if request_count > config.DDOS_THRESHOLD:
            threat_score += 40  # Increased from 30
            attack_type = AttackType.DDOS
        else:
            threat_score += 20  # Increased from 15
    
    threat_score = min(threat_score, 100)
    
    # MORE AGGRESSIVE threat level determination
    # Block immediately if ANY critical pattern detected
    if attack_type != AttackType.NONE and pattern_score > 15:
        threat_level = ThreatLevel.CRITICAL
        recommended_action = "BLOCK"
        is_malicious = True
    # Block if ML model is highly confident
    elif lgb_prob > 0.65:  # Lowered from 0.7
        threat_level = ThreatLevel.CRITICAL
        recommended_action = "BLOCK"
        is_malicious = True
    # Block based on threat score
    elif threat_score >= 60:  # Lowered from 80
        threat_level = ThreatLevel.CRITICAL
        recommended_action = "BLOCK"
        is_malicious = True
    elif threat_score >= 45:  # Lowered from 60
        threat_level = ThreatLevel.MALICIOUS
        recommended_action = "BLOCK"
        is_malicious = True
    # Suspicious activity - still block but with lower severity
    elif threat_score >= 30 or iso_pred == -1:  # Lowered from 40
        threat_level = ThreatLevel.SUSPICIOUS
        recommended_action = "BLOCK"  # Changed from THROTTLE to BLOCK
        is_malicious = True  # Changed from False to True
    # Only allow if clearly benign
    else:
        threat_level = ThreatLevel.BENIGN
        recommended_action = "ALLOW"
        is_malicious = False
    
    # Calculate confidence
    confidence = min(
        (lgb_prob if lgb_prob > 0.5 else 1 - lgb_prob) * 
        (1 if pattern_score > 0 else 0.8),
        1.0
    )
    
    # Update IP reputation (MORE AGGRESSIVE penalties)
    if is_malicious:
        if threat_level == ThreatLevel.CRITICAL:
            score_delta = -25  # Increased from -15
        elif threat_level == ThreatLevel.MALICIOUS:
            score_delta = -20  # Increased from -10
        else:  # SUSPICIOUS
            score_delta = -10
        ip_reputation.update_reputation(ip, score_delta, f"Threat detected: {attack_type.value}")
        
        # Immediately block for critical threats
        if threat_level == ThreatLevel.CRITICAL:
            ip_reputation.block_ip(ip, f"Critical threat: {attack_type.value}")
    else:
        ip_reputation.update_reputation(ip, 1, "Normal traffic")
    
    # Track behavior
    ip_reputation.track_behavior(
        ip,
        request_data.get("path", ""),
        request_data.get("headers", {}).get("user-agent", ""),
        False
    )
    
    # Store request history
    ip_reputation.request_history[ip].append({
        "timestamp": datetime.now().isoformat(),
        "path": request_data.get("path", ""),
        "method": request_data.get("method", ""),
        "threat_score": threat_score
    })
    
    # Get feature importance
    feature_importance = get_feature_importance(features)
    
    # Generate explanation
    explanation = generate_explanation({
        "attack_type": attack_type.value,
        "isolation_forest_anomaly": iso_pred == -1,
        "lightgbm_probability": lgb_prob,
        "ip_reputation": reputation,
        "rate_limited": rate_limited
    }, matched_patterns)
    
    return ThreatAnalysisResult(
        is_malicious=is_malicious,
        threat_level=threat_level.value,
        threat_score=threat_score,
        attack_type=attack_type.value,
        ip_reputation=reputation,
        rate_limited=rate_limited,
        confidence=confidence,
        recommended_action=recommended_action,
        feature_importance=feature_importance,
        explanation=explanation,
        timestamp=datetime.now().isoformat()
    )

# API ENDPOINTS
@app.post("/analyze")
async def analyze(request: Request):
    """Analyze incoming request for threats"""
    try:
        data = await request.json()
        ip = request.client.host
        
        request_data = {
            "method": data.get("method", "GET"),
            "path": data.get("path", "/"),
            "body": data.get("body", ""),
            "headers": data.get("headers", {})
        }
        
        result = await analyze_threat_advanced(request_data, ip)
        
        # STRICT BLOCKING - Block if malicious OR suspicious
        if result.is_malicious:
            status_code = 403
            status_message = "BLOCKED"
            
            if result.threat_level == ThreatLevel.CRITICAL.value:
                message = f"🚨 CRITICAL THREAT DETECTED - Request blocked immediately!"
            elif result.threat_level == ThreatLevel.MALICIOUS.value:
                message = f"⛔ MALICIOUS REQUEST DETECTED - Access denied!"
            else:  # SUSPICIOUS
                message = f"⚠️ SUSPICIOUS ACTIVITY DETECTED - Request blocked for security!"
            
            logger.warning(f"🚫 BLOCKED {ip} - {result.attack_type} | Score: {result.threat_score:.1f} | {result.explanation}")
            
            return JSONResponse(
                status_code=status_code,
                content={
                    "status": status_message,
                    "message": message,
                    "blocked": True,
                    "threat_level": result.threat_level,
                    "threat_score": result.threat_score,
                    "attack_type": result.attack_type,
                    "ip_reputation": result.ip_reputation,
                    "confidence": result.confidence,
                    "explanation": result.explanation,
                    "recommended_action": result.recommended_action,
                    "timestamp": result.timestamp
                }
            )
        
        # Only allow clearly benign traffic
        logger.info(f"✅ ALLOWED {ip} - Score: {result.threat_score:.1f}")
        
        return {
            "status": "ALLOWED",
            "message": "✅ Request approved - appears safe",
            "blocked": False,
            "threat_level": result.threat_level,
            "threat_score": result.threat_score,
            "ip_reputation": result.ip_reputation,
            "confidence": result.confidence,
            "timestamp": result.timestamp
        }
    
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "ERROR"}
        )

@app.get("/")
def root():
    return {
        "message": "Advanced AI-Powered API Gateway",
        "version": "2.0",
        "features": [
            "Hybrid ML ensemble (Isolation Forest + LightGBM)",
            "SHAP-based explainability",
            "Time-decay IP reputation",
            "Graduated response system",
            "Advanced feature engineering (25+ features)",
            "Behavioral pattern analysis",
            "DDoS detection",
            "Comprehensive audit logging"
        ],
        "endpoints": {
            "/analyze": "POST - Analyze request for threats",
            "/reputation/{ip}": "GET - Check IP reputation",
            "/stats": "GET - System statistics",
            "/whitelist": "POST - Manage whitelist",
            "/blocked": "GET - View blocked IPs",
            "/test": "GET - Test cases"
        }
    }

@app.get("/reputation/{ip}")
def get_reputation(ip: str):
    """Get comprehensive IP reputation information"""
    return {
        "ip": ip,
        "reputation_score": ip_reputation.get_reputation(ip),
        "is_blocked": ip_reputation.is_blocked(ip),
        "is_whitelisted": ip in ip_reputation.whitelist,
        "request_count": len(ip_reputation.request_counts.get(ip, [])),
        "endpoint_diversity": len(ip_reputation.endpoint_diversity.get(ip, set())),
        "failed_auth_count": ip_reputation.failed_auth_count.get(ip, 0),
        "user_agent_changes": len(ip_reputation.user_agent_changes.get(ip, [])),
        "throttle_factor": ip_reputation.get_throttle_factor(ip),
        "recent_history": ip_reputation.request_history.get(ip, [])[-5:]
    }

@app.get("/stats")
def get_statistics():
    """Get system-wide statistics"""
    total_ips = len(ip_reputation.reputation)
    blocked_ips = len(ip_reputation.blocked_ips)
    throttled_ips = len(ip_reputation.throttled_ips)
    whitelisted_ips = len(ip_reputation.whitelist)
    
    # Calculate reputation distribution
    reputations = list(ip_reputation.reputation.values())
    avg_reputation = np.mean(reputations) if reputations else 0
    
    # Total requests
    total_requests = sum(len(counts) for counts in ip_reputation.request_counts.values())
    
    return {
        "total_unique_ips": total_ips,
        "blocked_ips": blocked_ips,
        "throttled_ips": throttled_ips,
        "whitelisted_ips": whitelisted_ips,
        "total_requests_tracked": total_requests,
        "average_reputation": float(avg_reputation),
        "model_info": {
            "isolation_forest": {
                "n_estimators": iso_model.n_estimators,
                "contamination": iso_model.contamination
            },
            "lightgbm": {
                "n_estimators": lgb_model.n_estimators_,
                "num_features": len(AdvancedFeatureExtractor.FEATURE_NAMES)
            }
        }
    }

@app.post("/whitelist")
async def manage_whitelist(request: Request):
    """Add or remove IPs from whitelist"""
    try:
        data = await request.json()
        ip_address = data.get("ip")
        action = data.get("action", "add")  # add or remove
        
        if not ip_address:
            return JSONResponse(
                status_code=400,
                content={"error": "IP address required"}
            )
        
        if action == "add":
            ip_reputation.add_to_whitelist(ip_address)
            return {
                "status": "success",
                "message": f"✅ IP {ip_address} added to whitelist",
                "ip": ip_address
            }
        elif action == "remove":
            if ip_address in ip_reputation.whitelist:
                ip_reputation.whitelist.remove(ip_address)
                return {
                    "status": "success",
                    "message": f"✅ IP {ip_address} removed from whitelist",
                    "ip": ip_address
                }
            else:
                return JSONResponse(
                    status_code=404,
                    content={"error": "IP not in whitelist"}
                )
        else:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid action. Use 'add' or 'remove'"}
            )
    
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

@app.get("/blocked")
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    blocked_list = []
    for ip, blocked_time in ip_reputation.blocked_ips.items():
        time_remaining = 86400 - (datetime.now() - blocked_time).total_seconds()
        blocked_list.append({
            "ip": ip,
            "blocked_since": blocked_time.isoformat(),
            "time_remaining_seconds": max(0, int(time_remaining)),
            "reputation_score": ip_reputation.reputation.get(ip, 0)
        })
    
    return {
        "total_blocked": len(blocked_list),
        "blocked_ips": blocked_list
    }

@app.post("/unblock")
async def unblock_ip(request: Request):
    """Manually unblock an IP (human-in-the-loop override)"""
    try:
        data = await request.json()
        ip_address = data.get("ip")
        
        if not ip_address:
            return JSONResponse(
                status_code=400,
                content={"error": "IP address required"}
            )
        
        if ip_address in ip_reputation.blocked_ips:
            del ip_reputation.blocked_ips[ip_address]
            ip_reputation.reputation[ip_address] = 0  # Reset reputation
            logger.info(f"🔓 Manually unblocked IP {ip_address}")
            
            return {
                "status": "success",
                "message": f"✅ IP {ip_address} has been unblocked",
                "ip": ip_address,
                "new_reputation": 0
            }
        else:
            return JSONResponse(
                status_code=404,
                content={"error": "IP is not blocked"}
            )
    
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

@app.get("/test")
def test_cases():
    """Example test cases for various attack types"""
    return {
        "usage": "Send these payloads to /analyze endpoint to test detection",
        "benign_request": {
            "method": "GET",
            "path": "/api/users/123",
            "body": "",
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "accept": "application/json",
                "host": "api.example.com"
            }
        },
        "sql_injection": {
            "method": "POST",
            "path": "/login",
            "body": "username=admin' OR '1'='1'--&password=anything",
            "headers": {
                "content-type": "application/x-www-form-urlencoded"
            }
        },
        "xss_attack": {
            "method": "POST",
            "path": "/comment",
            "body": "<script>alert('XSS Attack')</script><img src=x onerror=alert('XSS')>",
            "headers": {
                "content-type": "text/html"
            }
        },
        "path_traversal": {
            "method": "GET",
            "path": "/files/../../../../etc/passwd",
            "body": "",
            "headers": {}
        },
        "command_injection": {
            "method": "POST",
            "path": "/execute",
            "body": "command=ls -la; cat /etc/passwd && whoami",
            "headers": {}
        },
        "ddos_simulation": {
            "note": "Send 250+ requests within 60 seconds from same IP",
            "method": "GET",
            "path": "/api/data",
            "body": "",
            "headers": {}
        },
        "brute_force": {
            "note": "Send multiple failed authentication attempts",
            "method": "POST",
            "path": "/login",
            "body": "username=admin&password=wrong_password",
            "headers": {}
        }
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": True,
        "version": "2.0"
    }

@app.get("/features")
def get_feature_list():
    """Get list of features used by ML models"""
    return {
        "total_features": len(AdvancedFeatureExtractor.FEATURE_NAMES),
        "features": AdvancedFeatureExtractor.FEATURE_NAMES,
        "feature_categories": {
            "protocol": ["method_encoded", "path_length", "body_length", "header_count"],
            "pattern_based": ["quote_count", "html_tag_count", "traversal_patterns", "sql_keywords"],
            "reputation": ["ip_reputation", "request_rate", "failed_auth_ratio"],
            "entropy": ["entropy_body", "entropy_path", "payload_entropy"],
            "behavioral": ["endpoint_diversity", "user_agent_changes", "request_interval_variance"],
            "temporal": ["time_of_day", "is_weekend"]
        }
    }

@app.post("/feedback")
async def submit_feedback(request: Request):
    """Submit feedback for false positives/negatives (human-in-the-loop learning)"""
    try:
        data = await request.json()
        ip = data.get("ip")
        was_correct = data.get("was_correct", True)
        actual_threat = data.get("actual_threat", False)
        comments = data.get("comments", "")
        
        if was_correct:
            logger.info(f"✅ Correct detection confirmed for IP {ip}")
        else:
            if actual_threat:
                # False negative - should have been blocked
                logger.warning(f"⚠️ False negative reported for IP {ip}: {comments}")
                ip_reputation.update_reputation(ip, -20, "False negative feedback")
            else:
                # False positive - should not have been blocked
                logger.warning(f"⚠️ False positive reported for IP {ip}: {comments}")
                ip_reputation.update_reputation(ip, 15, "False positive feedback")
                # Unblock if currently blocked
                if ip in ip_reputation.blocked_ips:
                    del ip_reputation.blocked_ips[ip]
        
        return {
            "status": "success",
            "message": "Feedback received and processed",
            "ip": ip,
            "new_reputation": ip_reputation.get_reputation(ip)
        }
    
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

# =============================================================================
# STARTUP & SHUTDOWN EVENTS
# =============================================================================
@app.on_event("startup")
async def startup_event():
    logger.info("="*60)
    logger.info("🚀 Advanced AI-Powered API Gateway Starting...")
    logger.info("="*60)
    logger.info("✅ Models loaded successfully")
    logger.info(f"✅ Feature extraction: {len(AdvancedFeatureExtractor.FEATURE_NAMES)} features")
    logger.info(f"✅ Isolation Forest: {iso_model.n_estimators} estimators")
    logger.info(f"✅ LightGBM: {lgb_model.n_estimators_} estimators")
    logger.info("="*60)

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("👋 Shutting down API Gateway...")
    logger.info(f"📊 Total IPs tracked: {len(ip_reputation.reputation)}")
    logger.info(f"🚫 IPs blocked: {len(ip_reputation.blocked_ips)}")

# RUN SERVER
if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 Advanced AI-Powered API Gateway v2.0")
    print("="*70)
    print("📍 Server: http://localhost:8000")
    print("📖 Interactive Docs: http://localhost:8000/docs")
    print("📊 ReDoc: http://localhost:8000/redoc")
    print("🧪 Test Cases: http://localhost:8000/test")
    print("📈 Statistics: http://localhost:8000/stats")
    print("🔒 Blocked IPs: http://localhost:8000/blocked")
    print("="*70)
    print("\n✨ New Features:")
    print("  • 25+ advanced features with behavioral analysis")
    print("  • SHAP-based explainability for decisions")
    print("  • Graduated response (throttle → block)")
    print("  • Human-in-the-loop feedback system")
    print("  • Comprehensive IP reputation tracking")
    print("  • Real-time DDoS detection")
    print("  • Whitelist management")
    print("  • Advanced audit logging")
    print("="*70 + "\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
