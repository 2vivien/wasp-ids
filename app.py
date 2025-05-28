from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime, timezone
import re
from functools import wraps
import queue
import threading
import atexit
import time 
from ids_capture import PacketCaptureThread
from ids_engine import DetectionEngine

try:
    from ids_capture import PacketCaptureThread
    from ids_engine import DetectionEngine
    IDS_MODULES_LOADED = True
except ImportError as e:
    print(f"Warning: Could not import IDS modules (ids_capture, ids_engine): {e}. IDS will not run.")
    IDS_MODULES_LOADED = False
    class PacketCaptureThread: 
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def join(self, *args, **kwargs): pass
        def is_alive(self): return False
        def stop(self): pass # Added stop method for placeholder
        
    class DetectionEngine: 
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def join(self, *args, **kwargs): pass
        def is_alive(self): return False
        def stop(self): pass # Added stop method for placeholder

app = Flask(__name__)
CORS(app)

app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://vivien:vivien@localhost:5432/wasp_ids'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CAPTURE_INTERFACE'] = 'wlp2s0' # Default capture interface

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    accepted_terms = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PortScanLog(db.Model):
    __tablename__ = 'port_scan_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_ip = db.Column(db.String(45), nullable=False)
    destination_port = db.Column(db.Integer, nullable=False) # Use 0 for "Multiple"
    protocol = db.Column(db.String(10), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='MEDIUM', nullable=False)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(), # Default is UTC, isoformat() is fine
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port if self.destination_port != 0 else "Multiple",
            'protocol': self.protocol,
            'scan_type': self.scan_type,
            'severity': self.severity,
            'details': self.details
        }

packet_queue = queue.Queue()
capture_stop_event = threading.Event()
engine_stop_event = threading.Event()
capture_thread_instance_global = None # Renamed to avoid conflict
engine_thread_instance_global = None  # Renamed to avoid conflict

def log_alert_to_db(
    scan_type,
    timestamp, # Expected to be a datetime object
    source_ip,
    destination_ip,
    destination_port, # Can be int or "Multiple"
    protocol,
    details,
    severity="MEDIUM",
    source_port=None # Can be int or None
):
    print(f"[DATABASE_LOG_ATTEMPT] Alert received: Type={scan_type}, SrcIP={source_ip}, DstIP={destination_ip}:{destination_port}, Proto={protocol}, Sev={severity}")
    with app.app_context():
        try:
            port_to_log = 0 # Default for "Multiple" or unparseable
            if isinstance(destination_port, int):
                port_to_log = destination_port
            elif isinstance(destination_port, str) and destination_port.isdigit():
                port_to_log = int(destination_port)
            # If destination_port is "Multiple" or other non-digit string, it remains 0

            alert_timestamp_obj = timestamp # Already a datetime object from engine
            if not isinstance(alert_timestamp_obj, datetime): # Fallback if not
                 alert_timestamp_obj = datetime.now(timezone.utc)


            valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            normalized_severity = severity.upper() if isinstance(severity, str) and severity.upper() in valid_severities else "MEDIUM"
            
            source_port_int = None
            if source_port is not None:
                if isinstance(source_port, str) and source_port.isdigit():
                    source_port_int = int(source_port)
                elif isinstance(source_port, int):
                    source_port_int = source_port
            
            log_entry = PortScanLog(
                timestamp=alert_timestamp_obj,
                source_ip=str(source_ip),
                source_port=source_port_int,
                destination_ip=str(destination_ip),
                destination_port=port_to_log,
                protocol=str(protocol),
                scan_type=str(scan_type),
                severity=normalized_severity,
                details=str(details)
            )

            db.session.add(log_entry)
            db.session.commit()
            print(f"[DATABASE_LOG_SUCCESS] Alert logged: ID={log_entry.id}, Type={scan_type}, SrcIP={source_ip}, DstIP={destination_ip}:{port_to_log}")

        except Exception as e:
            db.session.rollback()
            print(f"[DATABASE_LOG_FAILURE] Failed to log alert: {e}")
            print(f"Alert Data: Type={scan_type}, TS={timestamp}, SrcIP={source_ip}, SrcPort={source_port}, DstIP={destination_ip}, DstPort={destination_port}, Proto={protocol}, Sev={severity}")
            import traceback
            traceback.print_exc()
def log_alert(scan_type, severity, timestamp, source_ip, destination_ip, protocol, details=None, destination_port=None):
    with app.app_context():
        log = Log(timestamp=timestamp, source_ip=source_ip, destination_ip=destination_ip,
                  protocol=protocol, scan_type=scan_type, severity=severity, details=details,
                  user_id=1, destination_port=destination_port) # Assuming a default user for now
        db.session.add(log)
        db.session.commit()
        print(f"Alert logged: [{severity}] {scan_type} from {source_ip} to {destination_ip}:{destination_port} ({protocol}) - {details}")

def start_ids_threads():
    global capture_thread_instance_global
    global engine_thread_instance_global
    global stop_event_global
    global ids_queue_global

    stop_event_global = threading.Event()
    ids_queue_global = queue.Queue()

    capture_thread_instance_global = PacketCaptureThread(
        data_queue=ids_queue_global,
        interface= "wlp2s0",
        stop_event=stop_event_global
    )
    capture_thread_instance_global.daemon = True
    capture_thread_instance_global.start()
    print("Packet capture thread started.")

    engine_thread_instance_global = DetectionEngine(
        input_queue=ids_queue_global,
        log_alert_callback=log_alert,
        stop_event=stop_event_global
    )
    engine_thread_instance_global.daemon = True
    engine_thread_instance_global.start()
    print("Detection engine thread started.")

    print("IDS threads started.")


    capture_interface = app.config.get('CAPTURE_INTERFACE', 'wlp2s0')
    print(f"Attempting to start IDS packet capture on interface: {capture_interface}")

    capture_thread_instance_global = PacketCaptureThread(
        data_queue=packet_queue,
        interface=capture_interface,
        stop_event=capture_stop_event
    )
    capture_thread_instance_global.daemon = True 
    
    engine_thread_instance_global = DetectionEngine(
        input_queue=packet_queue,
        log_alert_callback=log_alert_to_db,
        stop_event=engine_stop_event
    )
    engine_thread_instance_global.daemon = True

    capture_thread_instance_global.start()
    engine_thread_instance_global.start()

    # --- MANUAL PACKET INJECTION FOR TESTING - COMMENTED OUT ---
    # print("[App] Manual test packet injection is currently COMMENTED OUT.")
    """
    if packet_queue: 
        print("[App] Injecting a manual test SYN packet into the queue...")
        test_syn_packet = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "TCP",
            "source_ip": "10.0.0.99",
            "source_port": 12345,
            "destination_ip": "192.168.1.200",
            "destination_port": 80, # This should be an int
            "flags": {
                "SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False
            },
            "details": "Manual test SYN packet injection from app.py",
            "severity": "HIGH" 
        }
        packet_queue.put(test_syn_packet)
        print(f"[App] Test SYN packet injected: {test_syn_packet}")
    """
    # --- END MANUAL PACKET INJECTION FOR TESTING ---
    
    print("IDS capture and detection engine threads started.")

def stop_ids_threads():
    if not IDS_MODULES_LOADED:
        return

    print("Stopping IDS threads...")
    global capture_thread_instance_global, engine_thread_instance_global

    if capture_stop_event: capture_stop_event.set()
    if engine_stop_event: engine_stop_event.set()

    if capture_thread_instance_global and capture_thread_instance_global.is_alive():
        print("Joining packet capture thread...")
        capture_thread_instance_global.join(timeout=5)
        if capture_thread_instance_global.is_alive(): print("Packet capture thread did not join in time.")
    
    if engine_thread_instance_global and engine_thread_instance_global.is_alive():
        print("Joining detection engine thread...")
        engine_thread_instance_global.join(timeout=5)
        if engine_thread_instance_global.is_alive(): print("Detection engine thread did not join in time.")
    
    print("IDS threads processing for stop complete.")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return render_template('denied.html') # Or jsonify error for API routes
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    # ... (registration logic remains the same) ...
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    role = data.get('role', '') # Expect 'admin' or 'analyste'
    accepted_terms = data.get('accepted_terms', False)

    if not re.fullmatch(r'^[a-zA-Z0-9_.-]{3,20}$', username): # Adjusted regex
        return jsonify({"error": "Nom d'utilisateur invalide (3-20 caractères, alphanumérique, _, ., -)"}), 400
    if not re.fullmatch(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email): # Standard email regex
        return jsonify({"error": "Adresse email invalide"}), 400
    if password != confirm_password:
        return jsonify({"error": "Les mots de passe ne correspondent pas"}), 400
    if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#-])[A-Za-z\d@$!%*?&_#-]{8,}$', password): # Stricter password
        return jsonify({"error": "Mot de passe trop faible (min 8 caractères, 1 maj, 1 min, 1 chiffre, 1 spécial)"}), 400
    if role not in ['admin', 'analyste']:
        return jsonify({"error": "Rôle invalide (doit être 'admin' ou 'analyste')"}), 400
    if not accepted_terms: # This should be a boolean true
        return jsonify({"error": "Vous devez accepter les conditions d'utilisation"}), 400
    
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Nom d'utilisateur ou email déjà utilisé"}), 409 # 409 Conflict

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_pw, role=role, accepted_terms=True)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Inscription réussie. Vous pouvez maintenant vous connecter."}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Erreur lors de l'inscription : {e}")
        return jsonify({"error": "Erreur serveur lors de l'inscription. Veuillez réessayer."}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    # ... (login logic remains the same) ...
    identifier = data.get('identifier', '').strip() # Can be username or email
    password = data.get('password', '')

    if not identifier or not password:
        return jsonify({"error": "Nom d'utilisateur/email et mot de passe requis"}), 400

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user) # session cookie is set here
        return jsonify({
            "message": "Connexion réussie",
            "user": {"username": user.username, "role": user.role}, # Send some user info
            "redirect": "/dashboard" # Suggest redirect to client
        }), 200

    return jsonify({"error": "Identifiants invalides"}), 401


# ROUTE DE DECONNEXION
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ROUTES PUBLIQUES
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/registration')
def registration():
    return render_template('registration.html')


# ROUTES PROTEGEES
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)

@app.route('/alert')
@login_required
def alert():
    return render_template('alert.html')

@app.route('/journal')
@login_required
def journal():
    return render_template('journal.html')

@app.route('/setting')
@login_required
@admin_required
def setting():
    return render_template('setting.html')

@app.route('/user')
@login_required
@admin_required
def user():
    return render_template('user.html')

@app.route('/pcap')
@login_required
def pcap():
    return render_template('pcap.html')


# PAGE 404 PERSONNALISÉE
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404



@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 15, type=int) # Number of items per page
        
        query = PortScanLog.query.order_by(PortScanLog.timestamp.desc())
        
        # Filter by severity if provided
        severity_filter = request.args.get('severity')
        if severity_filter and severity_filter.upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            query = query.filter(PortScanLog.severity == severity_filter.upper())

        # Filter by scan_type if provided
        scantype_filter = request.args.get('scan_type')
        if scantype_filter:
            query = query.filter(PortScanLog.scan_type.ilike(f"%{scantype_filter}%")) # Case-insensitive search

        # Filter by IP if provided (searches in both source_ip and destination_ip)
        ip_filter = request.args.get('ip')
        if ip_filter:
            query = query.filter(
                (PortScanLog.source_ip.ilike(f"%{ip_filter}%")) |
                (PortScanLog.destination_ip.ilike(f"%{ip_filter}%"))
            )
            
        logs_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        logs_data = [log.to_dict() for log in logs_pagination.items]
        
        return jsonify({
            "logs": logs_data,
            "total": logs_pagination.total,
            "pages": logs_pagination.pages,
            "current_page": logs_pagination.page,
            "has_next": logs_pagination.has_next,
            "has_prev": logs_pagination.has_prev
        }), 200
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return jsonify({"error": "Failed to fetch logs"}), 500


@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith('/api/'):
        return jsonify(error="Not Found", message=str(e)), 404
    return render_template('404.html'), 404

# Remove the @app.before_first_request decorator as it's deprecated
# def create_tables():
#     print("Ensuring database tables are created...")
#     db.create_all()
#     print("Database tables checked/created.")

if __name__ == '__main__':
    with app.app_context():
        print("Ensuring database tables are created...")
        db.create_all()
        print("Database tables checked/created.")
    
    if IDS_MODULES_LOADED:
        atexit.register(stop_ids_threads)
        # Delay starting threads slightly to allow Flask app to initialize if needed,
        # or start them in a separate thread to not block app startup.
        # For now, direct start is fine with use_reloader=False
        start_ids_threads()
    else:
        print("Flask app starting without IDS functionality due to module import errors.")
        
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)
