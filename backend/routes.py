import re
from pathlib import Path
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify, session
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from backend.config import Config

from backend.extensions import db
from backend.models import User, Scan

auth_bp = Blueprint("auth", __name__)

# Attempt to load trained ML spam pipeline
try:
    import joblib
    MODEL_PATH = Path(__file__).resolve().parent.parent / "spam_detector_pipeline.joblib"
    spam_model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
except Exception:
    spam_model = None


def classify_email_threat(subject: str, body: str):
    full_text = f"{subject} {body}".lower()

    # Specific threat categories with pattern heuristics
    categories = {
        "Credential Phishing": {
            "patterns": [
                (r"\b(verify|update|validate|confirm)\s+(your\s+)?(account|password|identity|banking|wallet|login|credentials)\b", 35, "Requests sensitive credential or account validation"),
                (r"\b(suspended|terminated|deactivated|unauthorized\s+access|security\s+alert|compromised)\b", 25, "Coercive warning regarding account standing"),
                (r"\b(reset\s+password|click\s+here\s+to\s+login|sign\s+in\s+to\s+verify)\b", 30, "Prompts immediate credential entry"),
            ],
            "score": 0,
            "flags": []
        },
        "Financial Scam": {
            "patterns": [
                (r"\b(wire\s+transfer|gift\s+card|crypto|bitcoin|usdt|western\s+union)\b", 35, "Requests non-standard or untraceable payment methods"),
                (r"\b(overdue\s+invoice|payment\s+pending|remittance|tax\s+refund|settlement\s+amount)\b", 25, "Unsolicited invoice, refund, or settlement notice"),
                (r"\b(winner|lottery|prize|reward|claim\s+now|grant|inheritance|million\s+dollars)\b", 30, "Advance-fee or fake windfall incentive"),
            ],
            "score": 0,
            "flags": []
        },
        "Executive Impersonation (BEC)": {
            "patterns": [
                (r"\b(are\s+you\s+available|quick\s+task|need\s+a\s+favor|handle\s+this\s+discreetly|keep\s+this\s+confidential)\b", 30, "Urgent, confidential executive inquiry style"),
                (r"\b(dean|principal|director|ceo|cfo|head\s+of\s+department|faculty\s+advisor)\b", 20, "Authority figure invocation"),
                (r"\b(in\s+a\s+meeting|cannot\s+take\s+calls|sent\s+from\s+my\s+iphone|sent\s+from\s+my\s+mobile)\b", 20, "Excuses preventing direct verification"),
            ],
            "score": 0,
            "flags": []
        },
        "Malware / Payload Delivery": {
            "patterns": [
                (r"\.(exe|scr|vbs|bat|cmd|iso|img|xlsm|docm)\b", 40, "References high-risk executable or macro attachment"),
                (r"\b(enable\s+macros|enable\s+editing|open\s+attached\s+zip|view\s+protected\s+document)\b", 35, "Prompts disabling security controls for payload"),
            ],
            "score": 0,
            "flags": []
        }
    }

    # Evaluate heuristic patterns across all categories
    for data in categories.values():
        for pattern, weight, desc in data["patterns"]:
            if re.search(pattern, full_text):
                data["score"] += weight
                data["flags"].append(desc)

    # General indicators: Links and URL obfuscation
    global_flags = []
    global_penalty = 0
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", full_text)
    if urls:
        global_flags.append(f"Contains {len(urls)} external URL link(s)")
        if any(re.search(r"\b(bit\.ly|tinyurl|is\.gd|t\.co|shorturl\.at|cutt\.ly)\b", u) for u in urls):
            global_penalty += 20
            global_flags.append("Contains shortened URL obscuring destination")

    # Determine highest threat vector
    ranked_cats = sorted(categories.items(), key=lambda item: item[1]["score"], reverse=True)
    top_category, top_data = ranked_cats[0]

    raw_threat_score = top_data["score"] + global_penalty
    threat_likelihood = min(raw_threat_score, 100)

    # Verdict assignment
    if threat_likelihood < 30:
        threat_type = "Legitimate / Safe"
        severity = "Low"
        combined_flags = ["No distinct malicious tactics detected", "Standard conversational vocabulary"]
    else:
        threat_type = top_category
        severity = "Critical" if threat_likelihood >= 70 else "Moderate"
        combined_flags = top_data["flags"] + global_flags

    return {
        "threat_type": threat_type,
        "threat_likelihood": threat_likelihood,
        "severity": severity,
        "flags": combined_flags,
        "category_breakdown": {
            name: min(info["score"], 100) for name, info in categories.items()
        }
    }


def classify_url_threat(raw_url: str):
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    full_target = f"{hostname}{path}"

    score = 0
    flags = []
    indicators = {
        "IP Address Hostname": False,
        "Suspicious TLD": False,
        "URL Shortener": False,
        "Phishing Keywords in Path": False,
        "Excessive Subdomains": False
    }

    # 1. IP address instead of domain name
    if re.search(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$", hostname):
        score += 45
        indicators["IP Address Hostname"] = True
        flags.append("Direct IP address used as host instead of a registered domain")

    # 2. Known URL shorteners
    shorteners = [r"\bbit\.ly\b", r"\btinyurl\.com\b", r"\bis\.gd\b", r"\bt\.co\b", r"\bshorturl\.at\b", r"\bcutt\.ly\b"]
    if any(re.search(pat, hostname) for pat in shorteners):
        score += 35
        indicators["URL Shortener"] = True
        flags.append("Shortened link obscuring actual destination")

    # 3. High-risk TLDs
    suspicious_tlds = [r"\.xyz$", r"\.top$", r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$", r"\.gq$", r"\.buzz$", r"\.work$"]
    if any(re.search(pat, hostname) for pat in suspicious_tlds):
        score += 30
        indicators["Suspicious TLD"] = True
        flags.append("Domain utilizes a high-risk or commonly abused Top-Level Domain (TLD)")

    # 4. Excessive subdomains
    subdomains = hostname.split(".")
    if len(subdomains) > 4:
        score += 25
        indicators["Excessive Subdomains"] = True
        flags.append("Excessive subdomain depth often used in domain spoofing")

    # 5. Phishing keywords in URL path or hostname
    phish_keywords = ["login", "verify", "secure", "account", "banking", "wallet", "update", "signin", "auth", "confirm"]
    matched_kws = [kw for kw in phish_keywords if kw in full_target and not hostname.endswith(f"{kw}.com")]
    if matched_kws:
        score += 25
        indicators["Phishing Keywords in Path"] = True
        flags.append(f"Suspicious security/credential keywords in path: {', '.join(matched_kws[:3])}")

    threat_score = min(score, 100)

    if threat_score >= 60:
        verdict = "Malicious URL"
        severity = "Critical"
    elif threat_score >= 25:
        verdict = "Suspicious URL"
        severity = "Moderate"
    else:
        verdict = "Safe Domain"
        severity = "Low"
        flags = ["Valid domain structure", "No high-risk redirectors or spoofing patterns detected"]

    return {
        "verdict": verdict,
        "score": threat_score,
        "severity": severity,
        "flags": flags,
        "indicators": indicators,
        "parsed_domain": hostname
    }


@auth_bp.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({
            "status": "error",
            "message": "Name, email and password are required"
        }), 400

    if len(name) > 100 or len(email) > 150:
        return jsonify({
            "status": "error",
            "message": "Name or email is too long"
        }), 400

    if len(password) < 8:
        return jsonify({
            "status": "error",
            "message": "Password must be at least 8 characters"
        }), 400

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({
            "status": "error",
            "message": "An account with this email already exists"
        }), 409

    new_user = User(
        name=name,
        email=email,
        password_hash=generate_password_hash(password)
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Account registered successfully"
    }), 201


@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({
            "status": "error",
            "message": "Invalid email or password"
        }), 401

    session.clear()
    session["user_id"] = user.id

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email
        }
    }), 200


@auth_bp.route("/api/me", methods=["GET"])
def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "status": "error",
            "message": "You are not logged in"
        }), 401

    user = db.session.get(User, user_id)

    if not user:
        session.clear()
        return jsonify({
            "status": "error",
            "message": "User account not found"
        }), 401

    return jsonify({
        "status": "success",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email
        }
    }), 200


@auth_bp.route("/api/logout", methods=["POST"])
def logout():
    session.clear()

    return jsonify({
        "status": "success",
        "message": "Logout successful"
    }), 200


@auth_bp.route("/api/google-login", methods=["POST"])
def google_login():
    data = request.get_json(silent=True)
    if not data or "credential" not in data:
        return jsonify({"status": "error", "message": "Google token is required"}), 400

    token = data["credential"]

    try:
        id_info = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            Config.GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=60
        )

        email = id_info.get("email", "").lower()
        name = id_info.get("name", email.split("@")[0])

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email, password_hash="google_oauth")
            db.session.add(user)
            db.session.commit()

        session.clear()
        session["user_id"] = user.id

        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email
            }
        }), 200

    except ValueError as val_err:
        return jsonify({"status": "error", "message": f"Invalid Google token: {str(val_err)}"}), 401

    except Exception as gen_err:
        return jsonify({"status": "error", "message": str(gen_err)}), 500


@auth_bp.route("/api/analyze-email", methods=["POST"])
def analyze_email():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({
            "status": "error",
            "message": "Authentication required. Please log in."
        }), 401

    data = request.get_json(silent=True) or {}
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()

    if not subject and not body:
        return jsonify({
            "status": "error",
            "message": "Please provide an email subject or content to analyze."
        }), 400

    full_text = f"{subject} {body}".strip()

    # Multi-category threat analysis
    analysis = classify_email_threat(subject, body)

    # ML Classifier inference
    ml_prediction = None
    if spam_model:
        try:
            pred = spam_model.predict([full_text])[0]
            ml_prediction = "Spam / Phishing" if pred == 1 else "Legitimate"
            if pred == 1 and analysis["threat_likelihood"] < 60:
                analysis["threat_likelihood"] = max(analysis["threat_likelihood"], 70)
                analysis["severity"] = "Critical"
                analysis["flags"].append("AI Linear Classifier identified phishing text structure")
        except Exception:
            pass

    details_payload = {
        "threat_type": analysis["threat_type"],
        "severity": analysis["severity"],
        "flags": analysis["flags"],
        "category_breakdown": analysis["category_breakdown"],
        "ml_result": ml_prediction,
        "input_preview": (subject or body)[:100]
    }

    # Record scan in SQLite database
    scan_entry = Scan(
        user_id=user_id,
        scan_type="email",
        target=subject[:120] if subject else body[:120],
        result=analysis["threat_type"],
        score=analysis["threat_likelihood"],
        details=details_payload
    )
    db.session.add(scan_entry)
    db.session.commit()

    return jsonify({
        "status": "success",
        "threat_type": analysis["threat_type"],
        "threat_likelihood": analysis["threat_likelihood"],
        "severity": analysis["severity"],
        "flags": analysis["flags"],
        "breakdown": analysis["category_breakdown"],
        "ml_result": ml_prediction
    }), 200


@auth_bp.route("/api/scan-url", methods=["POST"])
def scan_url():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({
            "status": "error",
            "message": "Authentication required. Please log in."
        }), 401

    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "Please provide a URL to scan."
        }), 400

    analysis = classify_url_threat(url)

    details_payload = {
        "verdict": analysis["verdict"],
        "severity": analysis["severity"],
        "flags": analysis["flags"],
        "indicators": analysis["indicators"],
        "domain": analysis["parsed_domain"]
    }

    scan_entry = Scan(
        user_id=user_id,
        scan_type="url",
        target=url[:120],
        result=analysis["verdict"],
        score=analysis["score"],
        details=details_payload
    )
    db.session.add(scan_entry)
    db.session.commit()

    return jsonify({
        "status": "success",
        "verdict": analysis["verdict"],
        "score": analysis["score"],
        "severity": analysis["severity"],
        "flags": analysis["flags"],
        "domain": analysis["parsed_domain"]
    }), 200


@auth_bp.route("/api/dashboard-stats", methods=["GET"])
def dashboard_stats():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({
            "status": "error",
            "message": "Authentication required. Please log in."
        }), 401

    user_scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.created_at.desc()).all()

    total_scans = len(user_scans)
    threats_detected = sum(
        1 for s in user_scans 
        if s.score >= 35 or s.result not in ["Safe", "Legitimate / Safe", "Safe Domain"]
    )
    safe_scans = total_scans - threats_detected

    recent_activity = []
    for s in user_scans[:5]:
        recent_activity.append({
            "target": s.target,
            "type": s.scan_type.capitalize(),
            "result": s.result,
            "score": s.score,
            "date": s.created_at.strftime("%b %d, %Y %H:%M") if s.created_at else "Just now"
        })

    return jsonify({
        "status": "success",
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "safe_scans": safe_scans,
        "recent_scans": recent_activity
    }), 200


@auth_bp.route("/api/reports", methods=["GET"])
def get_reports():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({
            "status": "error",
            "message": "Authentication required. Please log in."
        }), 401

    scan_type = request.args.get("type", "all").strip().lower()
    severity_filter = request.args.get("severity", "all").strip().lower()

    query = Scan.query.filter_by(user_id=user_id)

    if scan_type in ["email", "url"]:
        query = query.filter_by(scan_type=scan_type)

    scans = query.order_by(Scan.created_at.desc()).all()

    report_data = []
    for s in scans:
        sev = "Low"
        if s.score >= 70:
            sev = "Critical"
        elif s.score >= 35:
            sev = "Moderate"

        if severity_filter != "all" and sev.lower() != severity_filter:
            continue

        report_data.append({
            "id": s.id,
            "target": s.target,
            "type": s.scan_type.capitalize(),
            "result": s.result,
            "score": s.score,
            "severity": sev,
            "details": s.details if isinstance(s.details, dict) else {},
            "date": s.created_at.strftime("%b %d, %Y %H:%M") if s.created_at else "N/A"
        })

    return jsonify({
        "status": "success",
        "total": len(report_data),
        "reports": report_data
    }), 200