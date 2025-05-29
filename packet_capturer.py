#!/usr/bin/env python3
import subprocess
from datetime import datetime, timezone
import re
import sys
import netifaces
import logging
import signal
import os
import threading
import time

# Configuration du logging
LOG_FILENAME = "packet_capturer.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILENAME),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PacketCapturer')

# Variables globales
INTERFACE = None
PACKET_COUNT = 0
UNPARSED_COUNT = 0
TCPDUMP_PACKET_STATS = {
    "captured": 0,
    "received_by_filter": 0,
    "dropped_by_kernel": 0
}

# Gestion des signaux
shutdown_flag = threading.Event()
tcpdump_process = None

def signal_handler(signum, frame):
    logger.info(f"\nSignal {signum} reçu. Arrêt en cours...")
    shutdown_flag.set()
    if tcpdump_process:
        try:
            tcpdump_process.terminate()
        except:
            pass
    print_summary()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def print_summary():
    """Affiche un résumé des statistiques de capture"""
    print("\n" + "="*50)
    print("Résumé de la capture:")
    print(f"- Paquets traités: {PACKET_COUNT}")
    print(f"- Lignes non parsées: {UNPARSED_COUNT}")
    if TCPDUMP_PACKET_STATS['captured'] > 0:
        print("\nStatistiques tcpdump:")
        print(f"- Capturés par tcpdump: {TCPDUMP_PACKET_STATS['captured']}")
        print(f"- Reçus par le filtre: {TCPDUMP_PACKET_STATS['received_by_filter']}")
        print(f"- Perdus par le kernel: {TCPDUMP_PACKET_STATS['dropped_by_kernel']}")
    print("="*50 + "\n")

def get_default_interface():
    """Récupère l'interface réseau par défaut"""
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
        return None
    except Exception as e:
        logger.warning(f"Erreur récupération interface: {e}")
        return None

def check_interface_exists(interface_name):
    """Vérifie si l'interface existe"""
    try:
        return interface_name in netifaces.interfaces()
    except Exception as e:
        logger.error(f"Erreur vérification interface: {e}")
        return False

def list_available_interfaces():
    """Liste les interfaces disponibles"""
    try:
        interfaces = netifaces.interfaces()
        logger.info(f"Interfaces disponibles: {', '.join(interfaces)}")
        return interfaces
    except Exception as e:
        logger.error(f"Erreur listage interfaces: {e}")
        return []

# Initialisation de l'interface
INTERFACE = get_default_interface()
if not INTERFACE:
    available_interfaces = list_available_interfaces()
    common_interfaces = ['eth0', 'wlan0', 'wlp2s0', 'enp0s3', 'en0']
    for iface in common_interfaces:
        if iface in available_interfaces:
            INTERFACE = iface
            break
    if not INTERFACE and available_interfaces:
        INTERFACE = available_interfaces[0]

if INTERFACE and not check_interface_exists(INTERFACE):
    logger.warning(f"Interface '{INTERFACE}' non trouvée, utilisation de 'any'")
    INTERFACE = "any"

logger.info(f"Interface sélectionnée: {INTERFACE}")

def parse_tcpdump_line(line_str):
    """Parse une ligne de sortie tcpdump"""
    global UNPARSED_COUNT
    
    line_str = line_str.strip()
    if not line_str:
        return None

    # Patterns de regex optimisés
    tcp_udp_pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+"
        r"(?P<l2_proto>IP6?)\s+"
        r"(?P<source_ip>[\w.:-]+?)(?:\.(?P<source_port>\d+))?\s+>\s+"
        r"(?P<destination_ip>[\w.:-]+?)(?:\.(?P<destination_port>\d+))?:"
        r"(?:\s+Flags\s+\[(?P<flags>[^\]]+)\])?.*?"
    )

    icmp_pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+"
        r"(?P<l2_proto>IP6?)\s+"
        r"(?P<source_ip>[\w.:-]+)\s+>\s+(?P<destination_ip>[\w.:-]+):\s+(?:ICMP|ICMPv6)"
    )

    arp_pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+"
        r"ARP,\s+(?:Request who-has\s+(?P<arp_target_ip>[\w.:-]+)\s+tell\s+(?P<arp_sender_ip>[\w.:-]+)|"
        r"Reply\s+(?P<arp_is_at_ip>[\w.:-]+)\s+is-at\s+[\w:]+)"
    )

    # Parsing TCP/UDP
    match = tcp_udp_pattern.match(line_str)
    if match:
        data = match.groupdict()
        try:
            dt_obj = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            
            protocol = "TCP" if data.get('flags') else "UDP"
            flags = None
            if data.get('flags'):
                flags_present = []
                flag_map = {'S': 'SYN', 'F': 'FIN', 'R': 'RST', 'P': 'PSH', '.': 'ACK', 'U': 'URG'}
                for f, name in flag_map.items():
                    if f in data['flags']:
                        flags_present.append(name)
                flags = "|".join(flags_present) if flags_present else None

            return {
                "timestamp": dt_obj,
                "source_ip": data['source_ip'],
                "destination_ip": data['destination_ip'],
                "source_port": int(data['source_port']) if data['source_port'] else None,
                "destination_port": int(data['destination_port']) if data['destination_port'] else None,
                "protocol": protocol,
                "flags": flags
            }
        except Exception as e:
            logger.debug(f"Erreur parsing TCP/UDP: {e}")
            UNPARSED_COUNT += 1
            return None

    # Parsing ICMP
    icmp_match = icmp_pattern.match(line_str)
    if icmp_match:
        data = icmp_match.groupdict()
        try:
            dt_obj = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            return {
                "timestamp": dt_obj,
                "source_ip": data['source_ip'],
                "destination_ip": data['destination_ip'],
                "source_port": None,
                "destination_port": None,
                "protocol": "ICMPv6" if data['l2_proto'] == "IP6" else "ICMP",
                "flags": None
            }
        except Exception as e:
            logger.debug(f"Erreur parsing ICMP: {e}")
            UNPARSED_COUNT += 1
            return None

    # Parsing ARP
    arp_match = arp_pattern.match(line_str)
    if arp_match:
        data = arp_match.groupdict()
        try:
            dt_obj = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            source_ip = data.get('arp_sender_ip') or data.get('arp_is_at_ip')
            dest_ip = data.get('arp_target_ip') or "Broadcast"
            return {
                "timestamp": dt_obj,
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "source_port": None,
                "destination_port": None,
                "protocol": "ARP",
                "flags": None
            }
        except Exception as e:
            logger.debug(f"Erreur parsing ARP: {e}")
            UNPARSED_COUNT += 1
            return None

    UNPARSED_COUNT += 1
    if UNPARSED_COUNT <= 10 or UNPARSED_COUNT % 100 == 0:
        logger.debug(f"Ligne non parsée #{UNPARSED_COUNT}: {line_str[:100]}{'...' if len(line_str) > 100 else ''}")
    return None

def check_tcpdump_availability():
    """Vérifie si tcpdump est disponible"""
    try:
        result = subprocess.run(['which', 'tcpdump'], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("tcpdump non installé")
            return False
            
        result = subprocess.run(['sudo', '-n', 'tcpdump', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            logger.error("Permissions sudo requises pour tcpdump")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Erreur vérification tcpdump: {e}")
        return False

def start_capture(callback):
    """Démarre la capture réseau"""
    global PACKET_COUNT, tcpdump_process, TCPDUMP_PACKET_STATS
    
    if not check_tcpdump_availability():
        return

    tcpdump_command = [
        "sudo", "tcpdump",
        "-i", INTERFACE,
        "-tttt", "-n", "-l",
        "-B", "4096",
        "ip or ip6 or arp"
    ]

    logger.info(f"Démarrage capture sur {INTERFACE}")
    print(f"\nCapture en cours sur l'interface {INTERFACE}... (Ctrl+C pour arrêter)\n")
    print("Exemples de paquets capturés:\n")

    try:
        tcpdump_process = subprocess.Popen(
            tcpdump_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
            encoding='utf-8',
            errors='replace'
        )

        def monitor_stderr():
            """Capture les statistiques de tcpdump depuis stderr"""
            stats_pattern = re.compile(r"(\d+) packets? captured")
            received_pattern = re.compile(r"(\d+) packets? received by filter")
            dropped_pattern = re.compile(r"(\d+) packets? dropped by kernel")
            
            while not shutdown_flag.is_set() and tcpdump_process.poll() is None:
                line = tcpdump_process.stderr.readline()
                if line:
                    line = line.strip()
                    logger.debug(f"tcpdump: {line}")
                    
                    # Capture des statistiques
                    match = stats_pattern.search(line)
                    if match:
                        TCPDUMP_PACKET_STATS['captured'] = int(match.group(1))
                    
                    match = received_pattern.search(line)
                    if match:
                        TCPDUMP_PACKET_STATS['received_by_filter'] = int(match.group(1))
                    
                    match = dropped_pattern.search(line)
                    if match:
                        TCPDUMP_PACKET_STATS['dropped_by_kernel'] = int(match.group(1))

        stderr_thread = threading.Thread(target=monitor_stderr, daemon=True)
        stderr_thread.start()

        # Variables pour l'affichage
        last_status_time = time.time()
        sample_count = 0
        
        while not shutdown_flag.is_set():
            line = tcpdump_process.stdout.readline()
            if not line:
                if tcpdump_process.poll() is not None:
                    break
                continue
                
            packet_data = parse_tcpdump_line(line)
            if packet_data:
                PACKET_COUNT += 1
                callback(packet_data)
                
                # Afficher les 5 premiers paquets et ensuite 1 paquet toutes les 100 captures
                if sample_count < 5 or PACKET_COUNT % 100 == 0:
                    proto = packet_data['protocol']
                    src = f"{packet_data['source_ip']}:{packet_data.get('source_port', '')}"
                    dst = f"{packet_data['destination_ip']}:{packet_data.get('destination_port', '')}"
                    flags = f" [{packet_data.get('flags', '')}]" if packet_data.get('flags') else ""
                    print(f"[{proto}]{flags} {src} -> {dst}")
                    sample_count += 1
                
                # Afficher le statut toutes les secondes
                current_time = time.time()
                if current_time - last_status_time >= 1:
                    print(f"\rPaquets traités: {PACKET_COUNT} | Non parsés: {UNPARSED_COUNT} | En cours...", end="", flush=True)
                    last_status_time = current_time

    except Exception as e:
        logger.error(f"Erreur capture: {e}")
    finally:
        if tcpdump_process:
            tcpdump_process.terminate()
            try:
                tcpdump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump_process.kill()
                
        print("\n")  # Nouvelle ligne après le statut
        logger.info("Capture arrêtée")
        print_summary()
if __name__ == '__main__':
    def test_callback(packet):
        """Callback de test pour afficher les premiers paquets"""
        if PACKET_COUNT <= 5:
            logger.info(f"Paquet #{PACKET_COUNT}: {packet['protocol']} {packet['source_ip']} -> {packet['destination_ip']}")
        elif PACKET_COUNT % 100 == 0:
            # Afficher un paquet périodiquement pour montrer que ça capture
            logger.info(f"Paquet #{PACKET_COUNT}: {packet['protocol']} {packet['source_ip']}:{packet.get('source_port', '')} -> {packet['destination_ip']}:{packet.get('destination_port', '')}")

    try:
        start_capture(test_callback)
    except Exception as e:
        logger.error(f"Erreur: {e}")
    finally:
        print_summary()