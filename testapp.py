from flask import Flask, request, jsonify, render_template, redirect, url_for, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime, timezone
import re
from functools import wraps
import sys
import threading
import random  # Ajouté pour la sélection aléatoire
from packet_capturer import start_capture as start_packet_capture, tcpdump_process # MODIFICATION: Ajout de tcpdump_process
from detection_engine import DetectionEngine
from log_manager import save_alert_to_db  # Added import
import logging
from logging.handlers import RotatingFileHandler
from queue import Queue
import atexit # MODIFICATION: Ajout de atexit pour le nettoyage à la sortie

capture_thread = None
capture_active = False
capture_lock = threading.Lock()

detection_engine_instance = None
ids_thread_running = False
packet_queue = Queue()  # Créer une queue pour passer les paquets
# Configuration du logging global de l'application Flask
# app.logger (utilisé plus bas) sera configuré par Flask par défaut.

# Configuration du logging spécifique aux alertes IDS et logs de journal
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [IDS_EVENT] %(%(module)s.py)s:%(lineno)d - %(message)s')  # MODIFICATION: Ajout de module et line number
handler = RotatingFileHandler('ids_events.log', maxBytes=10 * 1024 * 1024, backupCount=5)  # Nom de fichier plus générique
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)

# Logger utilisé pour les alertes du moteur de détection ET les logs d'activité TCP pour le journal
event_logger = logging.getLogger('IDS_Event_Logger')  # Renommé pour plus de clarté
event_logger.addHandler(handler)
event_logger.setLevel(logging.INFO)
event_logger.propagate = False

app = Flask(__name__)
CORS(app)

app.secret_key = 'supersecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://vivien:vivien@localhost:5432/wasp_ids'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Ceci est le nom de l'endpoint/fonction pour la page de login
login_manager.login_message_category = "info"
login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."


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

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


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
    scan_type = db.Column(db.String(100), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    details = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<IDSLog {self.id} - {self.scan_type} from {self.source_ip}>'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            app.logger.warning(
                f"Accès non autorisé à une route admin par l'utilisateur {current_user.username if current_user.is_authenticated else 'Anonyme'} à {request.url}")
            return render_template('denied.html'), 403
        return f(*args, **kwargs)

    return decorated_function


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    role = data.get('role', '')
    accepted_terms = data.get('accepted_terms', False)

    errors = {}
    if not re.fullmatch(r'^[a-zA-Z0-9_.-]{3,20}$', username):
        errors['username'] = "Nom d'utilisateur invalide (3-20 caractères, alphanumérique, _, ., -)."
    if not re.fullmatch(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        errors['email'] = "Adresse email invalide."
    if password != confirm_password:
        errors['confirm_password'] = "Les mots de passe ne correspondent pas."
    if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_#-])[A-Za-z\d@$!%*?&_#-]{8,30}$', password):
        errors['password'] = "Mot de passe faible (min 8 caractères, 1 maj, 1 min, 1 chiffre, 1 spécial)."
    if role not in ['admin', 'analyste']:
        errors['role'] = "Rôle invalide sélectionné."
    if not accepted_terms:
        errors['accepted_terms'] = "Vous devez accepter les conditions d'utilisation."
    
    if User.query.filter_by(username=username).first():
        errors['username_exists'] = "Ce nom d'utilisateur est déjà pris."
    if User.query.filter_by(email=email).first():
        errors['email_exists'] = "Cette adresse email est déjà utilisée."

    if errors:
        return jsonify({"errors": errors}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_pw, role=role, accepted_terms=True)

    try:
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"Nouvel utilisateur enregistré : {username} ({email}), rôle: {role}")
        return jsonify({"message": "Inscription réussie ! Vous pouvez maintenant vous connecter."}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur serveur lors de l'inscription de {username}: {e}", exc_info=True)
        return jsonify({"error": "Une erreur serveur est survenue. Veuillez réessayer plus tard."}), 500


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

        # Démarrer la capture et l'IDS après connexion (AVEC GESTION DES ERREURS)
        with capture_lock:
            global capture_thread, capture_active, ids_thread_running, detection_engine_instance
            if not capture_active:
                try:
                    capture_thread = threading.Thread(
                        target=start_packet_capture,
                        args=(process_packet_callback,),
                        daemon=True
                    )
                    capture_thread.start()
                    capture_active = True
                    app.logger.info(f"Capture démarrée pour l'utilisateur {user.username}")
                except Exception as e:
                    app.logger.error(f"Erreur démarrage capture: {type(e).__name__} - {e}", exc_info=True)  # Ajout de exc_info
                    return jsonify({"error": "Erreur lors du démarrage de la capture"}), 500  # Gestion de l'erreur

            if not ids_thread_running:
                try:
                    # detection_engine_instance est initialisé avec input_queue et log_alert_callback
                    detection_engine_instance = DetectionEngine(input_queue=packet_queue, log_alert_callback=log_alert)
                    ids_thread = threading.Thread(target=detection_engine_instance.run, daemon=True)
                    ids_thread.start()
                    ids_thread_running = True
                    app.logger.info("Thread de détection IDS démarré.")
                except Exception as e:
                    app.logger.error(f"Erreur démarrage IDS: {type(e).__name__} - {e}", exc_info=True)  # Ajout de exc_info
                    # Arrêter la capture si elle a démarré
                    if capture_active:
                        with capture_lock:
                            capture_active = False
                    return jsonify({"error": "Erreur lors du démarrage de l'IDS"}), 500  # Gestion de l'erreur

        return jsonify({
            "message": "Connexion réussie",
            "redirect": "/dashboard"
        }), 200

    return jsonify({"error": "Identifiants invalides"}), 401


@app.route('/logout')
@login_required
def logout():
    # Arrêter la capture
    with capture_lock:
        global capture_active
        if capture_active:
            capture_active = False
            app.logger.info("Capture arrêtée")
    app.logger.info(f"Utilisateur {current_user.username} déconnecté.")
    logout_user()
    return redirect(url_for('login'))  # Redirige vers la page de login après déconnexion


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/login')  # L'endpoint est 'login'
def login():  # La fonction s'appelle 'login' pour correspondre à l'endpoint
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  # Si déjà connecté, rediriger vers le dashboard
    return render_template('login.html')  # Afficher le formulaire de connexion si non connecté


@app.route('/registration')
def registration():
    if current_user.is_authenticated:
        return render_template('registration.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)


@app.route('/alert')
@login_required
def alert():
    alert_db_id = request.args.get('alert_db_id')
    return render_template('alert.html', alert_db_id=alert_db_id)


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


@app.route('/api/logs', methods=['GET'])
@login_required
def get_api_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)

        logs_query = IDSLog.query.order_by(IDSLog.timestamp.desc())
        logs_paginated = logs_query.paginate(page=page, per_page=per_page, error_out=False)

        logs_db = logs_paginated.items

        logs_list = []
        for log_entry in logs_db:
            timestamp_utc = log_entry.timestamp
            if timestamp_utc.tzinfo is None:
                timestamp_utc = timestamp_utc.replace(tzinfo=timezone.utc)
            else:
                timestamp_utc = timestamp_utc.astimezone(timezone.utc)

            log_data = {
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
            }
            if log_entry.scan_type == "Journal TCP Activity" and log_entry.details:
                match = re.match(r"\[.*?\]\s+(?P<level>\S+)\s+(?P<model>\S+):\s+(?P<message>.*?)\s*\(Src:",
                                 log_entry.details)
                if match:
                    log_data['journal_level'] = match.group('level')
                    log_data['journal_model'] = match.group('model')
                    log_data['journal_message'] = match.group('message').strip()

            logs_list.append(log_data)

        return jsonify({
            "logs": logs_list,
            "total_pages": logs_paginated.pages,
            "current_page": logs_paginated.page,
            "total_logs": logs_paginated.total
        })
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des logs pour /api/logs: {e}", exc_info=True)
        return jsonify({"error": "Impossible de récupérer les logs"}), 500


@app.route('/api/logs/alertes', methods=['GET'])
@login_required
def get_alert_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        alerts_query = IDSLog.query.filter(
            IDSLog.scan_type.isnot(None),
            IDSLog.scan_type != "Journal TCP Activity",
            IDSLog.severity.isnot(None)
        ).order_by(IDSLog.timestamp.desc())

        alerts_paginated = alerts_query.paginate(page=page, per_page=per_page, error_out=False)
        alert_logs = alerts_paginated.items

        logs_list = []
        for log_entry in alert_logs:
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
        return jsonify({
            "alerts": logs_list,
            "total_pages": alerts_paginated.pages,
            "current_page": alerts_paginated.page,
            "total_alerts": alerts_paginated.total
        }), 200
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des alertes : {e}", exc_info=True)
        return jsonify({"error": "Impossible de récupérer les alertes"}), 500


AVAILABLE_MODELS = ["Kitsune", "LUCID", "VertexAI"]


def map_severity_to_score(severity_str):
    if not severity_str:
        return round(random.uniform(0.1, 0.29), 2)
    s_lower = severity_str.lower()
    if s_lower in ["high", "critique"]:
        return round(random.uniform(0.85, 1.0), 2)
    if s_lower in ["medium", "moyen"]:
        return round(random.uniform(0.6, 0.84), 2)
    if s_lower in ["low", "faible", "info", "debug"]:
        return round(random.uniform(0.3, 0.59), 2)
    return round(random.uniform(0.1, 0.29), 2)

def determine_model_and_type(scan_type_str, severity_str):
    model = random.choice(AVAILABLE_MODELS)
    alert_type = "Anomalie Inconnue"

    if scan_type_str:
        scan_lower = scan_type_str.lower()
        if any(kw in scan_lower for kw in ["scan", "sweep"]):
            alert_type = "Scan de Ports"
            model = "Kitsune"
        elif "brute force" in scan_lower:
            alert_type = "Brute Force"
            model = "VertexAI"
        elif any(kw in scan_lower for kw in ["ddos", "flood"]):
            alert_type = "DDoS/Flood"
            model = "LUCID"
        elif any(kw in scan_lower for kw in ["zero-day", "exploit"]):
            alert_type = "Zero-Day/Exploit"
            model = random.choice(["LUCID", "VertexAI"])
        elif "malware" in scan_lower:
            alert_type = "Malware"
            model = "VertexAI"
        else:
            alert_type = scan_type_str.replace("_", " ").title()

    if severity_str:
        sev_lower = severity_str.lower()
        if sev_lower in ["high", "critique"] and model == "Kitsune":
            model = random.choice(["LUCID", "VertexAI"])
    return model, alert_type


@app.route('/api/dashboard/critical-alerts', methods=['GET'])
@login_required
def get_dashboard_critical_alerts():
    try:
        # Base query for critical alerts
        base_critical_alerts_query = IDSLog.query.filter(
            IDSLog.scan_type.isnot(None),
            IDSLog.scan_type != "Journal TCP Activity",
            IDSLog.severity.isnot(None),
            IDSLog.severity.notin_(['Low', 'Faible', 'Info', 'Debug', 'Unknown'])
        )

        # Get the total count of critical alerts
        total_critical_alerts_count = base_critical_alerts_query.count()

        # Get the top 5 critical alerts for display
        critical_logs_for_display = base_critical_alerts_query.order_by(IDSLog.timestamp.desc()).limit(5).all()

        alerts_list_for_display = []
        for log_entry in critical_logs_for_display:
            ts_utc = log_entry.timestamp.astimezone(timezone.utc) if log_entry.timestamp.tzinfo else log_entry.timestamp.replace(
                tzinfo=timezone.utc)
            model, alert_type = determine_model_and_type(log_entry.scan_type, log_entry.severity)
            score = map_severity_to_score(log_entry.severity)
            alerts_list_for_display.append({
                'id': log_entry.id,
                'timestamp': ts_utc.strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': log_entry.source_ip,
                'model': model,
                'type': alert_type,
                'threat_score': score,
                'destination_ip': log_entry.destination_ip,
                'protocol': log_entry.protocol,
                'severity': log_entry.severity
            })

        return jsonify({
            "alerts_for_display": alerts_list_for_display,
            "total_critical_count": total_critical_alerts_count
        }), 200
    except Exception as e:
        app.logger.error(f"Erreur API /dashboard/critical-alerts: {e}", exc_info=True)
        return jsonify({"error": "Err critical alerts"}), 500


@app.route('/api/alert/<int:alert_id>', methods=['GET'])
@login_required
def get_single_alert_details(alert_id):
    try:
        log_entry = IDSLog.query.get(alert_id)
        if not log_entry:
            return jsonify({"error": "Alerte non trouvée"}), 404

        ts_utc = log_entry.timestamp.astimezone(timezone.utc) if log_entry.timestamp.tzinfo else log_entry.timestamp.replace(
            tzinfo=timezone.utc)
        model, alert_type_derived = determine_model_and_type(log_entry.scan_type, log_entry.severity)
        severity_val = log_entry.severity if log_entry.severity else 'Unknown'
        score_val = map_severity_to_score(severity_val) # MODIFICATION: use severity_val not log_entry.severity

        reco = ['Isoler IP', 'Analyser flux', 'Vérifier logs cibles']
        if severity_val.lower() == 'medium':
            reco = ['Surveiller IP', 'Analyser détails alerte']
        elif severity_val.lower() in ['low', 'info', 'debug']:
            reco = ['Noter pour corrélation', 'Action immédiate non requise si isolé']

        payload = {
            'id': f"DB-{log_entry.id}",
            'timestamp': ts_utc.isoformat().replace('+00:00', 'Z'),
            'file': 'N/A (DB Event)',
            'sourceIP': log_entry.source_ip,
            'destIP': log_entry.destination_ip,
            'model': model,
            'score': score_val,
            'verdict': f"{'🚨' if severity_val.lower() in ['high','critique'] else ('⚠️' if severity_val.lower()=='medium' else 'ℹ️')} {alert_type_derived}",
            'severity': severity_val.lower(),
            'sourcePort': log_entry.source_port,
            'destPort': log_entry.destination_port,
            'protocol': log_entry.protocol,
            'payloadSize': 'N/A',
            'flowDuration': 'N/A',
            'kitsuneScore': score_val if model == "Kitsune" else round(random.uniform(0.1, 0.6), 2),
            'lucidDetection': 'Zero-Day Détecté' if model == "LUCID" and severity_val.lower() in ['high',
                                                                                                'critique'] else (
            'Anomalie Suspecte' if model == "LUCID" else 'Standard'),
            'vertexLabel': alert_type_derived if model == "VertexAI" else 'N/A',
            'vertexConfidence': score_val if model == "VertexAI" else round(random.uniform(0.3, 0.7), 2),
            'recommendations': reco,
            'raw_details': log_entry.details or "Aucun détail brut.",
            'scan_type': log_entry.scan_type,  # Original scan type from DB
            'type': alert_type_derived  # Derived alert type for display consistency
        }
        return jsonify(payload), 200
    except Exception as e:
        app.logger.error(f"Erreur API /alert/{alert_id}: {e}", exc_info=True)
        return jsonify({"error": "Err détail alerte"}), 500


@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"Route non trouvée (404): {request.url}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"Erreur interne du serveur (500): {request.url} - Erreur: {e}", exc_info=True)
    return render_template('500.html'), 500


# MODIFICATION: Ajout de la fonction cleanup_on_exit pour arrêter tcpdump proprement
def cleanup_on_exit():
    print("Shutting down IDS thread and tcpdump process...")
    # Tente de terminer le processus tcpdump s'il est actif
    global tcpdump_process
    if tcpdump_process and tcpdump_process.poll() is None:
        try:
            tcpdump_process.terminate()
            tcpdump_process.wait(timeout=5)
            print("tcpdump process terminated.")
        except Exception as e:
            event_logger.error(f"Error terminating tcpdump process: {e}")
            print(f"Error terminating tcpdump process: {e}")
    print("IDS cleanup complete.")


# Les variables globales detection_engine_instance et ids_thread_running sont déjà définies au début du fichier.
# detection_engine_instance = None # Redondant
# ids_thread_running = False # Redondant


def infer_tcp_log_level_and_message(packet_data):
    flags_str = packet_data.get('flags', "")
    flags = set(flags_str.split('|')) if flags_str else set()

    if 'SYN' in flags and 'ACK' not in flags:
        return "INFO", "Nouvelle tentative de connexion TCP"
    if 'SYN' in flags and 'ACK' in flags:
        return "INFO", "Accusé de réception de connexion TCP (SYN-ACK)"
    if 'RST' in flags:
        return "ERROR", "Connexion TCP réinitialisée (RST)"
    if 'FIN' in flags:
        return "INFO", "Demande de fin de connexion TCP (FIN)"
    if 'PSH' in flags and 'ACK' in flags:
        return "INFO", "Transmission de données TCP (PSH-ACK)"
    if 'ACK' in flags and not flags.intersection({'SYN', 'FIN', 'RST'}):
        return "INFO", "Accusé de réception de données TCP (ACK)"
    if flags.issuperset({'FIN', 'PSH', 'URG'}):
        return "WARNING", "Scan TCP inhabituel (Xmas Scan suspecté)"
    if not flags and packet_data.get('protocol') == 'TCP':
        return "WARNING", "Paquet TCP sans flags (Null Scan suspecté)"
    return "DEBUG", f"Activité TCP avec flags: {flags_str if flags_str else 'N/A'}"


def process_packet_callback(packet_data):
    """
    Callback pour traiter les paquets capturés et générer des alertes
    """
    if not packet_data:
        event_logger.warning("Paquet vide reçu dans le callback")
        return

    try:
        # Journalisation de base du paquet
        event_logger.debug(
            f"Paquet reçu - Proto: {packet_data.get('protocol')} "
            f"Src: {packet_data.get('source_ip')}:{packet_data.get('source_port')} "
            f"Dst: {packet_data.get('destination_ip')}:{packet_data.get('destination_port')}"
        )

        packet_queue.put(packet_data)

    except Exception as e:
        event_logger.error(f"Erreur critique dans process_packet_callback: {e}", exc_info=True)


def log_alert(scan_type, timestamp, source_ip, destination_ip, source_port=None, destination_port=None, protocol=None,
              severity=None, details=None):
    """
    Callback pour enregistrer les alertes dans la base de données.
    """
    alert_data = {
        'timestamp': timestamp,
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'source_port': source_port,
        'destination_port': destination_port,
        'protocol': protocol,
        'scan_type': scan_type,
        'severity': severity,
        'details': details
    }

    try:
        # Ajout de l'ID utilisateur si connecté
        # Noter: current_user n'est pas fiable dans un thread de fond sans app_context
        # Si vous avez besoin de l'ID utilisateur, il faudrait le passer depuis le contexte où l'alerte est générée.
        # Pour l'instant, on retire cette ligne ou on s'assure d'avoir un contexte d'application.
        # if current_user.is_authenticated: # Cette ligne pourrait causer un Runtime Error si pas de contexte
        #     alert_data['user_id'] = current_user.id

        # Pour les threads de fond qui accèdent à la base de données, il faut un app_context.
        with app.app_context():
            # Formatage des données manquantes
            alert_data.setdefault('timestamp', datetime.now(timezone.utc))
            alert_data.setdefault('details', 'Aucun détail supplémentaire')

            # Sauvegarde via log_manager
            if not save_alert_to_db(alert_data=alert_data, db_instance=db, IDSLog_model=IDSLog):
                event_logger.error(f"Échec sauvegarde alerte: {alert_data}")
            else:
                event_logger.info(f"Alerte sauvegardée: {alert_data.get('scan_type')}")
    except Exception as e:
        event_logger.error(f"Erreur traitement alerte: {e}", exc_info=True)


def handle_tcp_activity(packet_data):
    """Gère spécifiquement l'activité TCP"""
    try:
        level_str, message_str = infer_tcp_log_level_and_message(packet_data)
        model_str = random.choice(AVAILABLE_MODELS)

        # Préparation des données
        log_data = {
            'timestamp': packet_data.get('timestamp', datetime.now(timezone.utc)),
            'source_ip': packet_data.get('source_ip', 'N/A'),
            'destination_ip': packet_data.get('destination_ip', 'N/A'),
            'source_port': packet_data.get('source_port'),
            'destination_port': packet_data.get('destination_port'),
            'protocol': 'TCP',
            'scan_type': "Journal TCP Activity",
            'severity': {"INFO": "Low", "WARNING": "Medium", "ERROR": "High"}.get(level_str, "Low"),
            'details': (
                f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}] "
                f"{level_str} {model_str}: {message_str} "
                f"(Src: {packet_data.get('source_ip')}:{packet_data.get('source_port', 'N/A')} "
                f"Dst: {packet_data.get('destination_ip')}:{packet_data.get('destination_port', 'N/A')})"
            ),
            # 'user_id': current_user.id if current_user.is_authenticated else None # Retire ici, voir log_alert
        }

        # Sauvegarde en base
        with app.app_context(): # MODIFICATION: Ajout du contexte d'application
            log_entry = IDSLog(**log_data)
            db.session.add(log_entry)
            db.session.commit()

        # Journalisation
        log_method = getattr(event_logger, level_str.lower(), event_logger.info)
        log_method(f"TCP_ACTIVITY: {log_data['details']}")

    except Exception as e:
        event_logger.error(f"Erreur journalisation TCP: {e}", exc_info=True)
        if 'db' in locals() and db.session.is_active:
            db.session.rollback()


def start_ids_thread_func():
    global detection_engine_instance, ids_thread_running
    if ids_thread_running:
        app.logger.info("Le thread IDS est déjà en cours d'exécution.")
        return

    app.logger.info("Initialisation et démarrage du thread IDS...")
    # detection_engine_instance est initialisé avec input_queue et log_alert_callback
    detection_engine_instance = DetectionEngine(input_queue=packet_queue, log_alert_callback=log_alert)

    ids_thread = threading.Thread(target=detection_engine_instance.run, daemon=True)
    ids_thread.start()
    ids_thread_running = True
    app.logger.info("Thread IDS démarré.")


# INIT BDD ET LANCEMENT
if __name__ == '__main__':
    # Use a single application context for all setup and initialization tasks
    with app.app_context():
        # 1. Initialize the database
        db.create_all()
        print("Base de données initialisée (création des tables si nécessaire).")
        current_app.logger.info("Base de données initialisée.")

        # 2. Start the background IDS thread.
        # This function contains logging, so it MUST be called within the context.
        # start_ids_thread_func()  # MODIFICATION: IDS thread will now only start upon user login via api_login route (commenté car déjà géré dans api_login)

        # 3. Log the server startup message
        print("Démarrage du serveur Flask...")
        current_app.logger.info("Démarrage du serveur Flask...")

    # MODIFICATION: Enregistrer la fonction de nettoyage pour être appelée à la sortie de l'application
    atexit.register(cleanup_on_exit)

    # 4. Run the application. This call is blocking and does not need to be in the context.
    # MODIFICATION: Ajout de allow_unsafe_werkzeug=True
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000,)
    