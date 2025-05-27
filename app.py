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
import time # Potentially for stop_ids_threads logic or if threads need it

# Assuming ids_capture.py and ids_engine.py are in the same directory or accessible
try:
    from ids_capture import PacketCaptureThread
    from ids_engine import DetectionEngine
    IDS_MODULES_LOADED = True
except ImportError as e:
    print(f"Warning: Could not import IDS modules (ids_capture, ids_engine): {e}. IDS will not run.")
    IDS_MODULES_LOADED = False
    # Define dummy/placeholder classes if actual IDS modules are not found.
    # This allows the Flask app to run its web server aspects without the IDS functionality,
    # preventing a hard crash if IDS components are missing or have issues.
    class PacketCaptureThread: # type: ignore # Placeholder class
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def join(self, *args, **kwargs): pass
        def is_alive(self): return False # type: ignore
        
    class DetectionEngine: # type: ignore # Placeholder class
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def join(self, *args, **kwargs): pass
        def is_alive(self): return False # type: ignore

app = Flask(__name__)
CORS(app)

# Clé secrète pour les sessions
app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://vivien:vivien@localhost:5432/wasp_ids'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirige vers /login si non connecté
login_manager.login_message_category = "info"


# MODELE UTILISATEUR
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    accepted_terms = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# MODELE PORT SCAN LOG
class PortScanLog(db.Model):
    __tablename__ = 'port_scan_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)  # Nouveau champ optionnel
    destination_ip = db.Column(db.String(45), nullable=False)
    destination_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='MEDIUM', nullable=False)  # Nouveau champ
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'source_ip': self.source_ip,
            'source_port': self.source_port,  # Ajouté
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'scan_type': self.scan_type,
            'severity': self.severity,  # Ajouté
            'details': self.details
        }

# --- Global Variables for IDS ---
packet_queue = queue.Queue() # Shared queue for passing packet data from capture to engine
capture_stop_event = threading.Event() # Event to signal the packet capture thread to stop
engine_stop_event = threading.Event()  # Event to signal the detection engine thread to stop
capture_thread = None # Will hold the PacketCaptureThread instance
engine_thread = None  # Will hold the DetectionEngine instance

# --- IDS Callback and Thread Management Functions ---

def log_alert_to_db(
    scan_type,
    timestamp,
    source_ip,
    destination_ip,
    destination_port,
    protocol,
    details,
    severity="MEDIUM",
    source_port=None
):
    """
    Logs security alerts to PostgreSQL database with complete error handling.
    Includes advanced filtering to ignore normal traffic and focus on real threats.
    """
    with app.app_context():
        try:
            # =============================================
            # 1. FILTRES AVANCÉS - IGNORER LES ACTIVITÉS NORMALES
            # =============================================
            
            # Ignorer les paquets de test internes
            if source_ip == "10.0.0.99" and destination_ip == "192.168.1.200":
                return
            
            # Liste des IPs locales à ignorer
            local_ips = {
                "127.0.0.1", "::1", "localhost",
                "0.0.0.0", "255.255.255.255", 
                "::", "ff02::1", "ff02::2"
            }
            if source_ip in local_ips or destination_ip in local_ips:
                return
            
            # Ignorer les réseaux privés (RFC 1918 + multicast)
            private_network_prefixes = (
                "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                "169.254.", "224.", "239.", "ff00::"
            )
            
            if any(source_ip.startswith(p) for p in private_network_prefixes) or \
               any(destination_ip.startswith(p) for p in private_network_prefixes):
                return
            
            # Ignorer les ports courants légitimes (HTTP, HTTPS, DNS, etc.)
            common_ports = {
                80, 443, 53, 123, 22, 25, 110, 143, 
                993, 995, 587, 3306, 5432, 3389, 5900
            }
            if isinstance(destination_port, int) and destination_port in common_ports:
                return
            
            # Ignorer les protocoles non suspects (ICMP ping par exemple)
            if protocol not in ("TCP", "UDP"):
                return
            
            # =============================================
            # 2. VALIDATION ET TRAITEMENT DES DONNÉES
            # =============================================
            
            # Process destination port
            port_to_log = 0
            if isinstance(destination_port, (int, str)):
                if str(destination_port).isdigit():
                    port_to_log = int(destination_port)
                elif destination_port == "Multiple":
                    port_to_log = 0  # Spécial pour les scans multi-ports

            # Process timestamp
            if isinstance(timestamp, str):
                timestamp = timestamp.replace('Z', '+00:00') if timestamp.endswith('Z') else timestamp
                try:
                    alert_timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    alert_timestamp = datetime.utcnow()
            else:
                alert_timestamp = timestamp or datetime.utcnow()

            # Validate severity
            valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            severity = severity.upper() if severity.upper() in valid_severities else "MEDIUM"

            # Process source port
            source_port_int = None
            if source_port is not None:
                if isinstance(source_port, str) and source_port.isdigit():
                    source_port_int = int(source_port)
                elif isinstance(source_port, int):
                    source_port_int = source_port

            # =============================================
            # 3. FILTRES SUPPLÉMENTAIRES BASÉS SUR LE CONTEXTE
            # =============================================
            
            # Ignorer les scans de services internes connus
            internal_services = {
                ("192.168.1.1", 80),  # Routeur local
                ("192.168.1.2", 22)   # Serveur SSH interne
            }
            if (destination_ip, destination_port) in internal_services:
                return
            
            # Ignorer les communications entre serveurs connus
            trusted_pairs = {
                ("192.168.1.10", "192.168.1.20"),
                ("192.168.1.10", "192.168.1.30")
            }
            if (source_ip, destination_ip) in trusted_pairs:
                return

            # =============================================
            # 4. ENREGISTREMENT DE L'ALERTE
            # =============================================
            
            # Create and save log entry
            log_entry = PortScanLog(
                timestamp=alert_timestamp,
                source_ip=source_ip,
                source_port=source_port_int,
                destination_ip=destination_ip,
                destination_port=port_to_log,
                protocol=protocol,
                scan_type=scan_type,
                severity=severity,
                details=details
            )

            db.session.add(log_entry)
            db.session.commit()

            # Debug logging
            port_info = f"{source_ip}:{source_port}" if source_port else source_ip
            print(f"[{severity}] {scan_type} detected from {port_info} to "
                  f"{destination_ip}:{destination_port or 'Multiple'}")

        except Exception as e:
            db.session.rollback()
            print(f"Failed to log alert: {str(e)}")
            print(f"Error context: {scan_type}, {source_ip}:{source_port}, "
                  f"{destination_ip}:{destination_port}, {severity}")


def start_ids_threads():
    """Initializes and starts the packet capture and detection engine threads."""
    if not IDS_MODULES_LOADED:
        print("IDS modules (ids_capture, ids_engine) not loaded. IDS threads will not start.")
        return

    global capture_thread, engine_thread # Refer to global variables to store thread instances.
    
    # Determine capture interface: Configurable via Flask app config (app.config['CAPTURE_INTERFACE']),
    # defaults to 'lo' (loopback interface).
    # 'lo' is safer for initial testing and doesn't usually require root for tcpdump.
    # Capturing on 'eth0' or other physical interfaces typically requires sudo/root privileges for tcpdump.
    capture_interface = app.config.get('CAPTURE_INTERFACE', 'lo') 
    print(f"Attempting to start IDS packet capture on interface: {capture_interface}")

    # Create and configure PacketCaptureThread.
    # The # type: ignore comments are used because PacketCaptureThread might be a dummy placeholder class
    # if the actual ids_capture module failed to import.
    capture_thread_instance = PacketCaptureThread( # type: ignore 
        data_queue=packet_queue, # Shared queue for sending data to DetectionEngine
        interface=capture_interface, # Interface to capture on
        stop_event=capture_stop_event # Event to signal thread termination
    )
    # Threads set as daemon will exit automatically when the main program (Flask app) exits.
    capture_thread_instance.daemon = True 
    
    # Create and configure DetectionEngine thread.
    engine_thread_instance = DetectionEngine( # type: ignore
        input_queue=packet_queue, # Shared queue for receiving data from PacketCaptureThread
        log_alert_callback=log_alert_to_db, # Pass the database logging function as callback
        stop_event=engine_stop_event # Event to signal thread termination
    )
    engine_thread_instance.daemon = True

    # Start the threads. They will begin executing their run() methods.
    capture_thread_instance.start()
    engine_thread_instance.start()

    # --- BEGIN MANUAL PACKET INJECTION FOR TESTING ---
    if packet_queue:  # Ensure packet_queue is initialized
        print("[App] Injecting a manual test SYN packet into the queue...")
        test_syn_packet = {
            "timestamp": datetime.now(timezone.utc).isoformat(),  # Current time in UTC
            "protocol": "TCP",
            "source_ip": "10.0.0.99",         # Test source IP
            "source_port": 12345,             # Test source port
            "destination_ip": "192.168.1.200", # Test destination IP
            "destination_port": 80,           # Test destination port
            "flags": {
                "SYN": True, 
                "ACK": False, 
                "FIN": False, 
                "RST": False, 
                "PSH": False, 
                "URG": False
            },
            "details": "Manual test SYN packet injection",
            "severity": "HIGH"                # Ajout du champ severity
        }
        packet_queue.put(test_syn_packet)
        print(f"[App] Test SYN packet injected: {test_syn_packet}")
        
        # Alternative avec un objet PacketData si c'est ce que votre système attend
        """
        test_packet_data = PacketData(
            timestamp=datetime.now(timezone.utc),
            protocol="TCP",
            source_ip="10.0.0.99",
            source_port=12345,
            destination_ip="192.168.1.200",
            destination_port=80,
            flags={"SYN": True, "ACK": False},
            details="Manual test SYN packet injection"
        )
        packet_queue.put(test_packet_data)
        print(f"[App] Test PacketData injected: {test_packet_data}")
        """
        
        # For testing the "No Response Scan" logic, we can also inject a SYN-ACK response.
        # This helps verify if the 'responded' flag gets set in no_response_probe_tracker.
        # The source/dest are swapped compared to the SYN.
        # This part is optional but useful for comprehensive testing.
        # test_syn_ack_packet = {
        #     "timestamp": (datetime.utcnow() + timedelta(milliseconds=100)).isoformat() + 'Z',
        #     "protocol": "TCP",
        #     "source_ip": "192.168.1.200", # Original destination is now source
        #     "source_port": 80,
        #     "destination_ip": "10.0.0.99", # Original source is now destination
        #     "destination_port": 12345,
        #     "flags": {"SYN": True, "ACK": True},
        #     "details": "Manual test SYN-ACK packet injection"
        # }
        # packet_queue.put(test_syn_ack_packet)
        # print(f"[App] Test SYN-ACK packet injected: {test_syn_ack_packet}")
    # --- END MANUAL PACKET INJECTION FOR TESTING ---
    
    # Store instances in global variables (optional, but can be useful for state checking or direct interaction if needed).
    capture_thread = capture_thread_instance
    engine_thread = engine_thread_instance
    print("IDS capture and detection engine threads started.")

def stop_ids_threads():
    """
    Signals and waits for the IDS threads to stop. 
    This function is registered with `atexit` to be called automatically on application shutdown.
    """
    if not IDS_MODULES_LOADED:
        # print("IDS modules not loaded. Nothing to stop.") # Can be verbose during shutdown.
        return

    print("Stopping IDS threads...")
    # Signal threads to stop by setting their respective stop events.
    # The threads' run() methods should periodically check these events.
    if capture_stop_event:
        capture_stop_event.set()
    if engine_stop_event:
        engine_stop_event.set()

    global capture_thread, engine_thread # Refer to global variables holding thread instances.

    # Wait for the capture thread to join (finish its execution).
    current_capture_thread = capture_thread # Use a local copy for thread-safety during this check.
    if current_capture_thread and current_capture_thread.is_alive():
        print("Joining packet capture thread...")
        current_capture_thread.join(timeout=5) # Wait up to 5 seconds for the thread to finish.
        if current_capture_thread.is_alive():
            print("Packet capture thread did not join in time.") # Log if it doesn't stop as expected.
    
    # Wait for the detection engine thread to join.
    current_engine_thread = engine_thread # Use a local copy.
    if current_engine_thread and current_engine_thread.is_alive():
        print("Joining detection engine thread...")
        current_engine_thread.join(timeout=5) # Wait up to 5 seconds.
        if current_engine_thread.is_alive():
            print("Detection engine thread did not join in time.") # Log if it doesn't stop.
    
    print("IDS threads processing for stop complete.")


# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Décorateur pour vérifier le rôle admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return render_template('denied.html')
        return f(*args, **kwargs)
    return decorated_function


# ROUTE D'INSCRIPTION
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    role = data.get('role', '')
    accepted_terms = data.get('accepted_terms', False)

    if not re.fullmatch(r'^[a-zA-Z0-9]{3,16}$', username):
        return jsonify({"error": "Nom d'utilisateur invalide"}), 400
    if not re.fullmatch(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        return jsonify({"error": "Adresse email invalide"}), 400
    if password != confirm_password:
        return jsonify({"error": "Les mots de passe ne correspondent pas"}), 400
    if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$', password):
        return jsonify({"error": "Mot de passe trop faible"}), 400
    if role not in ['admin', 'analyste']:
        return jsonify({"error": "Rôle invalide"}), 400
    if not accepted_terms:
        return jsonify({"error": "Conditions non acceptées"}), 400
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Nom d'utilisateur ou email déjà utilisé"}), 400
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_pw, role=role, accepted_terms=True)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Inscription réussie"}), 201
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Erreur serveur"}), 500


# ROUTE DE LOGIN
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')

    if not identifier or not password:
        return jsonify({"error": "Champs requis"}), 400

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({
            "message": "Connexion réussie",
            "redirect": "/dashboard"
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

# NOUVEL ENDPOINT API POUR LES LOGS
@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    logs = PortScanLog.query.order_by(PortScanLog.timestamp.desc()).all()
    return jsonify([log.to_dict() for log in logs]), 200


# PAGE 404 PERSONNALISÉE
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# --- Application Initialization and Startup ---
if __name__ == '__main__':
    # Ensure database tables are created within the application context.
    # This needs to be done before the app runs or any requests are handled.
    with app.app_context():
        db.create_all() # Creates tables defined by SQLAlchemy models if they don't already exist.
    
    if IDS_MODULES_LOADED: # Only start IDS threads if the necessary modules were loaded successfully.
        # Register stop_ids_threads to be called automatically when the Python interpreter exits.
        # This ensures a graceful shutdown of the background IDS threads.
        atexit.register(stop_ids_threads)
        
        # Start the IDS background threads.
        start_ids_threads()
    else:
        # Log a message if IDS functionality is disabled due to import errors.
        print("Flask app starting without IDS functionality due to module import errors.")
        
    # Run the Flask development server.
    # use_reloader=False is important when using background threads with Flask's built-in development server.
    # The reloader can cause threads to be started multiple times or not cleaned up properly upon reload.
    # For production deployments, a proper WSGI server (like Gunicorn or uWSGI) should be used instead of app.run().
    app.run(debug=True, use_reloader=False)