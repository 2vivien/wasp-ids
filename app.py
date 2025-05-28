from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime, timezone
import re
from functools import wraps
import sys # Added for sys.stderr
import threading
from packet_capturer import start_capture as start_packet_capture
from detection_engine import DetectionEngine
from log_manager import save_alert_to_db

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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# MODELE IDSLog
class IDSLog(db.Model):
    __tablename__ = 'ids_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(10), nullable=False)
    scan_type = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(10), nullable=True) 
    details = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<IDSLog {self.id}>'

# CHARGEMENT DE L'UTILISATEUR POUR FLASK-LOGIN
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

# API ROUTE FOR LOGS
@app.route('/api/logs', methods=['GET'])
@login_required
def get_api_logs():
    try:
        logs_db = IDSLog.query.order_by(IDSLog.timestamp.desc()).all()
        logs_list = []
        for log_entry in logs_db:
            # Ensure timestamp is timezone-aware (UTC) before formatting
            timestamp_utc = log_entry.timestamp
            if timestamp_utc.tzinfo is None:
                timestamp_utc = timestamp_utc.replace(tzinfo=timezone.utc)
            else:
                timestamp_utc = timestamp_utc.astimezone(timezone.utc)

            logs_list.append({
                'id': log_entry.id,
                'timestamp': timestamp_utc.isoformat().replace('+00:00', 'Z'),
                'source_ip': log_entry.source_ip,
                'destination_ip': log_entry.destination_ip,
                'source_port': log_entry.source_port,
                'destination_port': log_entry.destination_port,
                'protocol': log_entry.protocol,
                'scan_type': log_entry.scan_type,
                'severity': log_entry.severity,
                'details': log_entry.details
            })
        return jsonify(logs_list)
    except Exception as e:
        # Log the exception for server-side debugging
        print(f"Error fetching logs for /api/logs: {e}") 
        # import traceback
        # traceback.print_exc()
        return jsonify({"error": "Failed to retrieve logs"}), 500

# PAGE 404 PERSONNALISÉE
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- IDS Integration ---
detection_engine_instance = None
ids_thread_running = False
ids_stop_event = threading.Event() # This event is not yet used by packet_capturer to stop tcpdump

def process_packet_callback(packet_data):
    global detection_engine_instance
    if detection_engine_instance and packet_data: # Ensure engine is initialized and data is valid
        try:
            alerts = detection_engine_instance.process_packet(packet_data)
            if alerts:
                with app.app_context(): # Ensure app context for db operations
                    for alert in alerts:
                        print(f"ALERT DETECTED by IDS: {alert['scan_type']} from {alert['source_ip']}") # Server log
                        save_alert_to_db(alert, app) # 'app' is the Flask app instance
        except Exception as e:
            print(f"Error processing packet or saving alert: {e}", file=sys.stderr)

def start_ids_thread():
    global detection_engine_instance, ids_thread_running, ids_stop_event
    if ids_thread_running:
        print("IDS thread already running.")
        return

    print("Initializing and starting IDS thread...")
    # Initialize the engine when the thread starts, ensuring it's fresh if thread is ever restarted (not current design)
    detection_engine_instance = DetectionEngine() 
    ids_stop_event.clear() 

    # The current packet_capturer.start_packet_capture is blocking and runs tcpdump.
    # It does not currently accept ids_stop_event for a graceful shutdown of tcpdump.
    # The thread is set as a daemon, so it will exit when the main Flask app exits.
    thread = threading.Thread(target=start_packet_capture, args=(process_packet_callback,), daemon=True)
    thread.start()
    ids_thread_running = True
    print("IDS thread started.")

# INIT BDD ET LANCEMENT
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Start the IDS packet capture and detection thread
    start_ids_thread() 
    
    # Note: use_reloader=False is important when running background threads with Flask's dev server.
    # The daemon=True on the IDS thread means it will terminate when the main application exits.
    # A more robust stop mechanism for the tcpdump process within packet_capturer would
    # involve managing the subprocess.Popen object directly to send a SIGINT/SIGTERM.
    app.run(debug=True, use_reloader=False)