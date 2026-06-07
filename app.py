import os
import sys
import threading
import time
import datetime
from flask import Flask, request, jsonify, session, send_file, render_template_string
from flask_cors import CORS

# Add parent directory to path so imports work correctly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import init_db, get_user_by_username, add_user, get_all_users, add_threat, get_threat_history, get_threat_by_id, add_dataset_item, get_stats, delete_threat
from utils import extract_url_features, check_domain_rdap, analyze_email, clean_url
from model import predict_phishing_probability, train_model, MODEL_PATH
from pdf_gen import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# Ensure database is initialized
init_db()

# Global variables for clipboard monitoring
clipboard_active = False
last_clipboard_url = ""
clipboard_threats = [] # Queue of new clipboard threats detected in background
clipboard_lock = threading.Lock()

def clipboard_monitor_worker():
    global clipboard_active, last_clipboard_url, clipboard_threats
    import pyperclip
    print("[Clipboard Monitor] Background thread started.")
    
    while clipboard_active:
        try:
            content = pyperclip.paste()
            if content:
                content = content.strip()
                # Simple regex check for URL
                is_url = content.startswith("http://") or content.startswith("https://") or (
                    ("." in content) and (" " not in content) and (len(content) > 4) and not content.startswith("C:")
                )
                
                if is_url and content != last_clipboard_url:
                    last_clipboard_url = content
                    print(f"[Clipboard Monitor] Found URL: {content}")
                    
                    # Scan the URL
                    try:
                        # Clean if it lacks protocol
                        scan_url = content
                        if not scan_url.startswith("http"):
                            scan_url = "http://" + scan_url
                            
                        prob, _, reasons = predict_phishing_probability(scan_url)
                        score = int(prob * 100)
                        
                        classification = "Safe"
                        if score > 50:
                            classification = "Phishing"
                        elif score > 20:
                            classification = "Suspicious"
                            
                        # If suspicious or phishing, log to DB and add to alert queue
                        if classification in ["Phishing", "Suspicious"]:
                            # Log as system scan (user_id = 1 for admin or 0/None for public)
                            user_id = session.get('user_id', 1) # Default to admin if no session
                            threat_id = add_threat(
                                user_id=user_id,
                                scan_type="URL",
                                target=content,
                                risk_score=score,
                                classification=classification,
                                reasons=reasons
                            )
                            
                            # Add to queue for frontend alerts
                            with clipboard_lock:
                                clipboard_threats.append({
                                    "id": threat_id,
                                    "url": content,
                                    "risk_score": score,
                                    "classification": classification,
                                    "reasons": reasons,
                                    "time": datetime.datetime.now().strftime("%H:%M:%S")
                                })
                                # Keep queue small
                                if len(clipboard_threats) > 10:
                                    clipboard_threats.pop(0)
                                    
                            print(f"[Clipboard Monitor] Threat detected: {content} | Score: {score}%")
                    except Exception as scan_err:
                        print(f"[Clipboard Monitor] Error scanning: {scan_err}")
        except Exception as clip_err:
            # Clipboard read fail (can happen if clipboard is locked by another app)
            pass
            
        time.sleep(1.5)
        
    print("[Clipboard Monitor] Background thread stopped.")

# Auth Decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Forbidden. Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated_function


# --- HTML Serving Routes ---
@app.route('/')
def home():
    # We will serve templates/index.html which is our beautiful Single Page Application UI.
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            return render_template_string(f.read())
    else:
        return "<h2>PhishShield AI Static files are building... Please refresh in a moment.</h2>"


# --- API Routes ---

# Auth APIs
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user') # default role is user
    
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
        
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400
        
    user_id = add_user(username, password, role)
    if user_id is None:
        return jsonify({"error": "Username already exists."}), 400
        
    return jsonify({"success": "Registration successful. You can now log in."}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
        
    from database import verify_password
    user = get_user_by_username(username)
    if user and verify_password(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return jsonify({
            "id": user['id'],
            "username": user['username'],
            "role": user['role']
        })
        
    return jsonify({"error": "Invalid username or password."}), 401

@app.route('/api/auth/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    return jsonify({"success": "Logged out successfully."})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if 'user_id' in session:
        return jsonify({
            "logged_in": True,
            "user": {
                "id": session['user_id'],
                "username": session['username'],
                "role": session['role']
            }
        })
    return jsonify({"logged_in": False})


# Scanning APIs
@app.route('/api/scan/url', methods=['POST'])
@login_required
def scan_url_api():
    data = request.json or {}
    url = data.get('url')
    user_override = data.get('override', False) # True if the user manually marks this as Safe or Phishing override
    override_label = data.get('override_label', 0) # 0 = Safe, 1 = Phishing
    
    if not url:
        return jsonify({"error": "URL parameter is required."}), 400
        
    # Clean the URL
    url = clean_url(url)
    
    try:
        # Predict using Random Forest
        prob, features, reasons = predict_phishing_probability(url)
        score = int(prob * 100)
        
        classification = "Safe"
        if score > 50:
            classification = "Phishing"
        elif score > 20:
            classification = "Suspicious"
            
        # If user is overriding the classification (Admin/User override features)
        if user_override:
            # Add/update in custom training dataset
            add_dataset_item(url, override_label, source="user")
            
            # Recalculate score and reasons for user response
            score = 100 if override_label == 1 else 0
            classification = "Phishing" if override_label == 1 else "Safe"
            reasons = ["User classification override applied."] if override_label == 1 else ["User marked as legitimate domain."]
            
        # Log scan in Threat History database
        threat_id = add_threat(
            user_id=session['user_id'],
            scan_type="URL",
            target=url,
            risk_score=score,
            classification=classification,
            reasons=reasons
        )
        
        return jsonify({
            "id": threat_id,
            "url": url,
            "risk_score": score,
            "classification": classification,
            "reasons": reasons,
            "features": features
        })
    except Exception as e:
        return jsonify({"error": f"Error running URL scan: {str(e)}"}), 500

@app.route('/api/scan/email', methods=['POST'])
@login_required
def scan_email_api():
    data = request.json or {}
    email_content = data.get('email_content')
    
    if not email_content:
        return jsonify({"error": "Email content is required."}), 400
        
    try:
        # Analyze email keywords, links, urgency
        analysis = analyze_email(email_content)
        
        # Log to threat history
        # We store up to first 200 characters of email text as the target in DB
        db_target = email_content[:200]
        if len(email_content) > 200:
            db_target += "..."
            
        threat_id = add_threat(
            user_id=session['user_id'],
            scan_type="Email",
            target=db_target,
            risk_score=analysis['risk_score'],
            classification=analysis['classification'],
            reasons=analysis['reasons']
        )
        
        analysis["id"] = threat_id
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": f"Error analyzing email: {str(e)}"}), 500

@app.route('/api/domain-info', methods=['GET'])
@login_required
def domain_info_api():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain query parameter is required."}), 400
        
    try:
        info = check_domain_rdap(domain)
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve domain information: {str(e)}"}), 500


# Threat Log & Reports APIs
@app.route('/api/threats', methods=['GET'])
@login_required
def get_threats():
    # If admin, retrieve all threats; otherwise, only the current user's threats
    user_id = None if session.get('role') == 'admin' else session['user_id']
    threats = get_threat_history(user_id=user_id)
    
    # Format into list of dicts
    result = []
    import json
    for t in threats:
        try:
            reasons = json.loads(t['reasons'])
        except Exception:
            reasons = [t['reasons']]
            
        result.append({
            "id": t['id'],
            "user_id": t['user_id'],
            "username": t['username'],
            "type": t['type'],
            "target": t['target'],
            "risk_score": t['risk_score'],
            "classification": t['classification'],
            "reasons": reasons,
            "created_at": t['created_at']
        })
    return jsonify(result)

@app.route('/api/threats/<int:threat_id>', methods=['DELETE'])
@login_required
def delete_threat_api(threat_id):
    # Only allow deletion if user owns the record or is admin
    threat = get_threat_by_id(threat_id)
    if not threat:
        return jsonify({"error": "Threat record not found."}), 404
        
    if session.get('role') != 'admin' and threat['user_id'] != session['user_id']:
        return jsonify({"error": "Forbidden."}), 403
        
    delete_threat(threat_id)
    return jsonify({"success": "Threat record deleted successfully."})

@app.route('/api/threats/<int:threat_id>/report', methods=['GET'])
@login_required
def get_pdf_report(threat_id):
    threat = get_threat_by_id(threat_id)
    if not threat:
        return "<h3>Threat record not found.</h3>", 404
        
    if session.get('role') != 'admin' and threat['user_id'] != session['user_id']:
        return "<h3>Forbidden. Access denied.</h3>", 403
        
    import json
    try:
        reasons = json.loads(threat['reasons'])
    except Exception:
        reasons = [threat['reasons']]
        
    scan_data = {
        "target": threat['target'],
        "scan_type": threat['type'],
        "risk_score": threat['risk_score'],
        "classification": threat['classification'],
        "reasons": reasons,
        "username": threat['username'] or "Anonymous",
        "date": threat['created_at']
    }
    
    try:
        pdf_buffer = generate_pdf_report(scan_data)
        safe_filename = f"phishshield_report_{threat_id}.pdf"
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=safe_filename
        )
    except Exception as e:
        return f"<h3>Failed to generate PDF Report: {str(e)}</h3>", 500


# Clipboard Scanner Alerts APIs
@app.route('/api/clipboard/toggle', methods=['POST'])
@login_required
def toggle_clipboard():
    global clipboard_active
    data = request.json or {}
    enable = data.get('enable', False)
    
    if enable and not clipboard_active:
        clipboard_active = True
        t = threading.Thread(target=clipboard_monitor_worker, daemon=True)
        t.start()
        return jsonify({"status": "enabled", "message": "Clipboard scanning activated."})
    elif not enable and clipboard_active:
        clipboard_active = False
        return jsonify({"status": "disabled", "message": "Clipboard scanning deactivated."})
        
    return jsonify({"status": "enabled" if clipboard_active else "disabled"})

@app.route('/api/clipboard/new', methods=['GET'])
@login_required
def get_new_clipboard_threats():
    global clipboard_threats
    with clipboard_lock:
        threats = list(clipboard_threats)
        clipboard_threats.clear() # Clear after polling
    return jsonify(threats)


# Admin APIs
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users_list():
    users = get_all_users()
    return jsonify([{
        "id": u['id'],
        "username": u['username'],
        "role": u['role'],
        "created_at": u['created_at']
    } for u in users])

@app.route('/api/admin/retrain', methods=['POST'])
@admin_required
def retrain_model_api():
    try:
        sample_count = train_model()
        return jsonify({
            "success": f"Random Forest model retrained successfully on {sample_count} dataset records."
        })
    except Exception as e:
        return jsonify({"error": f"Failed to retrain model: {str(e)}"}), 500

@app.route('/api/admin/override', methods=['POST'])
@admin_required
def add_override():
    data = request.json or {}
    url = data.get('url')
    label = data.get('label') # 0 = Safe, 1 = Phishing
    
    if not url or label is None:
        return jsonify({"error": "URL and label are required."}), 400
        
    success = add_dataset_item(url, int(label), source="user")
    if success:
        return jsonify({"success": f"Domain {url} overridden successfully. Please retrain model to apply."})
    return jsonify({"error": "Failed to add dataset override."}), 500

@app.route('/api/admin/stats', methods=['GET'])
@login_required
def get_stats_api():
    # If admin, fetch global stats. Otherwise, fetch stats only for current user
    user_id = None if session.get('role') == 'admin' else session['user_id']
    stats = get_stats(user_id=user_id)
    return jsonify(stats)


# Start Flask Server
if __name__ == '__main__':
    print("==================================================")
    print("      PHISHSHIELD AI SECURITY SYSTEM SERVER       ")
    print("==================================================")
    print("1. Server running on: http://127.0.0.1:8000")
    print("2. Default Admin login: admin / Admin@123")
    print("3. Default User login:  user / User@123")
    print("==================================================")
    
    # Train model on startup if it doesn't exist
    if not os.path.exists(MODEL_PATH):
        print("[Startup] Model file not found. Generating training data...")
        try:
            train_model()
        except Exception as startup_err:
            print(f"[Startup] Failed to train model on startup: {startup_err}")
            
    # Run Flask application on port 8000
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)