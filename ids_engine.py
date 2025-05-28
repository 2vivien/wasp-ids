import threading
import time
import queue
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

class DetectionEngine(threading.Thread):
    _EXPECTED_ATTRIBUTES = [
        ("input_queue", "queue.Queue", "Queue for incoming PacketData"),
        ("log_alert_callback", "callable", "Function to handle alert logging"),
        ("stop_event", "threading.Event", "Event to signal thread termination"),
        ("packet_history", "defaultdict", "History of packets for analysis", deque),  # Corrected defaultdict usage
        ("nmap_syn_scan_rules", "list", "Rules for detecting Nmap SYN scans"),
        ("horizontal_scan_tracker", "defaultdict", "Tracker for horizontal scans", lambda: defaultdict(lambda: {'first_seen': None, 'ports': set()})),
        ("port_scan_threshold", "int", "Threshold for port scan detection"),
        ("port_scan_time_window", "int", "Time window for port scan detection"),
        ("syn_scan_tracker", "defaultdict", "Tracker for SYN scans", lambda: defaultdict(lambda: {'count': 0, 'first_seen': None})),
        ("syn_scan_threshold_count", "int", "Threshold for SYN scan detection"),
        ("syn_scan_time_window_seconds", "int", "Time window for SYN scan detection"),
        ("horizontal_scan_threshold_ports", "int", "Threshold for horizontal scan detection"),
        ("horizontal_scan_time_window_seconds", "int", "Time window for horizontal scan detection", 5),  # Default value!
        ("icmp_flood_tracker", "defaultdict", "Tracker for ICMP flood detection", lambda: {'count': 0, 'first_seen': None}),
        ("icmp_flood_threshold_count", "int", "Threshold for ICMP flood detection"),
        ("icmp_flood_time_window_seconds", "int", "Time window for ICMP flood detection"),
        ("udp_flood_tracker", "defaultdict", "Tracker for UDP flood detection", lambda: defaultdict(lambda: {'count': 0, 'first_seen': None, 'dest_ports': defaultdict(int)})),
        ("udp_flood_threshold_count", "int", "Threshold for UDP flood detection"),
        ("udp_flood_time_window_seconds", "int", "Time window for UDP flood detection"),
        ("http_flood_tracker", "defaultdict", "Tracker for HTTP flood detection", lambda: {'count': 0, 'first_seen': None}),
        ("http_flood_threshold_count", "int", "Threshold for HTTP flood detection"),
        ("http_flood_time_window_seconds", "int", "Time window for HTTP flood detection"),
        ("recent_alerts", "deque", "Queue of recent alerts"),
        ("alert_cooldown", "int", "Cooldown period for alerts"),
        ("last_cleanup", "datetime", "Timestamp of last cleanup"),
        ("cleanup_interval", "timedelta", "Interval for periodic cleanup"),
        ("no_response_probe_tracker", "defaultdict", "Tracker for no-response probes", lambda: defaultdict(lambda: defaultdict(lambda: {'timestamp': None, 'responded': False}))),
        ("NO_RESPONSE_PROBE_TIMEOUT_SECONDS", "int", "Timeout for no-response probes", 10),  # Default value!
        ("last_no_response_cleanup_time", "datetime", "Timestamp of last no-response cleanup"),
        ("no_response_alerted_sources", "dict", "Track sources that triggered no-response alerts"),
        ("SYN_SCAN_TARGET_PORT_THRESHOLD", "int", "Threshold for SYN scans to multiple ports"),
        ("SYN_SCAN_TARGET_TIME_WINDOW", "int", "Time window for SYN scans to multiple ports"),
    ]

    def __init__(self, input_queue, log_alert_callback, stop_event=None):
        super().__init__()
        self.input_queue = input_queue
        self.log_alert_callback = log_alert_callback
        self.stop_event = stop_event or threading.Event()
        self.setName("DetectionEngineThread")
        self.last_no_response_cleanup_time = datetime.now(timezone.utc)

        for item in self._EXPECTED_ATTRIBUTES:
            if len(item) == 4:
                name, type_hint, description, default_value = item
            elif len(item) == 3:
                name, type_hint, description = item
                default_value = None
            else:
                print(f"[ERROR] Unexpected item in _EXPECTED_ATTRIBUTES: {item}")
                continue

            if not hasattr(self, name):
                if "defaultdict" in type_hint:
                    if callable(default_value):
                        self_factory = default_value
                    elif default_value:
                        self_factory = default_value
                    else:
                        self_factory = None # Handle case where no default for defaultdict
                    setattr(self, name, defaultdict(self_factory) if self_factory else defaultdict())
                elif type_hint == "queue.Queue":
                    setattr(self, name, queue.Queue())
                elif type_hint == "threading.Event":
                    setattr(self, name, threading.Event())
                elif type_hint == "datetime":
                    setattr(self, name, datetime.now(timezone.utc))
                elif type_hint == "timedelta":
                    setattr(self, name, timedelta(seconds=0))
                elif default_value is not None:
                    setattr(self, name, default_value)
                elif type_hint == "list":
                    setattr(self, name, [])
                elif type_hint == "dict":
                    setattr(self, name, {})
                elif type_hint == "set":
                    setattr(self, name, set())
                elif type_hint == "int":
                    setattr(self, name, 0)
                elif type_hint == "str":
                    setattr(self, name, "")
                elif type_hint == "bool":
                    setattr(self, name, False)
                else:
                    setattr(self, name, None)

        # Any overrides or complex initialization *after* the loop
        self.nmap_syn_scan_rules = [
    {'port_range': range(1, 1001), 'syn_count': 50, 'time_window': 5},   # Rafale rapide
    {'port_range': range(1, 1001), 'syn_count': 100, 'time_window': 30},  # Activité soutenue
    {'port_range': range(1, 1001), 'syn_count': 200, 'time_window': 60}   # Scan très lent mais persistant
]

        print("DetectionEngine initialized.")

    def run(self):
        print("DetectionEngine run method started.")
        while not (self.stop_event and self.stop_event.is_set()):
            try:
                packet_data = self.input_queue.get(timeout=0.5)
                self.process_packet(packet_data)
                self.input_queue.task_done()
            except queue.Empty:
                pass
            except Exception as e:
                print(f"Error in DetectionEngine run: {e}")
                break
            finally:
                now = datetime.now(timezone.utc)
                if self.last_cleanup is None or (now - self.last_cleanup > self.cleanup_interval):
                    self.periodic_cleanup(now)
                    self.last_cleanup = now
        print("DetectionEngine run method finished.")

    def process_packet(self, packet_data):
        timestamp = packet_data.get('timestamp')
        source_ip = packet_data.get('source_ip')
        destination_ip = packet_data.get('destination_ip')
        destination_port = packet_data.get('destination_port')
        protocol = packet_data.get('protocol')
        flags = packet_data.get('tcp_flags', {})

        if self.is_nmap_syn_scan(source_ip, destination_ip, destination_port, flags, timestamp):
            self.log_alert_callback(
                scan_type="Nmap SYN Scan Detected",
                severity="HIGH",
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol,
                details=f"Nmap SYN scan detected from {source_ip} to {destination_ip}:{destination_port}"
            )
            return

        # Ajoutez ici d'autres logiques de détection si nécessaire

    def is_nmap_syn_scan(self, source_ip, dest_ip, dest_port, flags, timestamp):
        if not flags.get("SYN") or flags.get("ACK"):
            return False

        for rule in self.nmap_syn_scan_rules:
            if dest_port in rule['port_range']:
                self.packet_history[source_ip].append((dest_port, timestamp))
                while len(self.packet_history[source_ip]) > 100:
                    self.packet_history[source_ip].popleft()

                recent_syns = [p for p, t in self.packet_history[source_ip] if
                              t > timestamp - timedelta(seconds=rule['time_window']) and p == dest_port]
                if len(recent_syns) >= rule['syn_count']:
                    return True
        return False

    def periodic_cleanup(self, now):
        self._prune_packet_history(now)
        self._prune_syn_scan_tracker(now)
        self._prune_horizontal_scan_tracker(now)
        self._prune_icmp_flood_tracker(now)
        self._prune_udp_flood_tracker(now)
        self._prune_http_flood_tracker(now)
        self._prune_no_response_probe_tracker(now)

    def _prune_packet_history(self, now):
        for ip, history in self.packet_history.items():
            while history and now - self.dt_from_ts(history[0][1]) > timedelta(seconds=60):
                history.popleft()

    def _prune_syn_scan_tracker(self, now):
        for source_ip, targets in list(self.syn_scan_tracker.items()):
            for dest_ip, data in list(targets.items()):
                if data['first_seen'] and (now - data['first_seen']).total_seconds() > self.syn_scan_time_window_seconds * 2:
                    del self.syn_scan_tracker[source_ip][dest_ip]
            if not self.syn_scan_tracker[source_ip]:
                del self.syn_scan_tracker[source_ip]

    def _prune_horizontal_scan_tracker(self, now):
        for source_ip, targets in list(self.horizontal_scan_tracker.items()):
            for target, data in list(targets.items()):
                if data['first_seen'] and (now - data['first_seen']).total_seconds() > self.horizontal_scan_time_window_seconds * 2:
                    del self.horizontal_scan_tracker[source_ip][target]
            if not self.horizontal_scan_tracker[source_ip]:
                del self.horizontal_scan_tracker[source_ip]

    def _prune_icmp_flood_tracker(self, now):
        for source_ip, data in list(self.icmp_flood_tracker.items()):
            if data['first_seen'] and (now - data['first_seen']).total_seconds() > self.icmp_flood_time_window_seconds * 2:
                del self.icmp_flood_tracker[source_ip]

    def _prune_udp_flood_tracker(self, now):
        for source_ip, data in list(self.udp_flood_tracker.items()):
            if data['first_seen'] and (now - data['first_seen']).total_seconds() > self.udp_flood_time_window_seconds * 2:
                del self.udp_flood_tracker[source_ip]

    def _prune_http_flood_tracker(self, now):
        for source_ip, data in list(self.http_flood_tracker.items()):
            if data['first_seen'] and (now - data['first_seen']).total_seconds() > self.http_flood_time_window_seconds * 2:
                del self.http_flood_tracker[source_ip]

    def _prune_no_response_probe_tracker(self, now):
        if not hasattr(self, 'no_response_probe_tracker'):
            return

        cooldown_duration = getattr(self, 'HORIZONTAL_SCAN_TIME_WINDOW_SECONDS', 60) * 4 # Default to 60 if not found
        time_threshold = now - timedelta(seconds=cooldown_duration)

        for source_ip, targets in list(self.no_response_probe_tracker.items()):
            for target_ip, probes in list(targets.items()):
                for protocol, probe_data in list(probes.items()):
                    if probe_data['timestamp'] < time_threshold:
                        del self.no_response_probe_tracker[source_ip][target_ip][protocol]
                if not self.no_response_probe_tracker[source_ip][target_ip]:
                    del self.no_response_probe_tracker[source_ip][target_ip]
            if not self.no_response_probe_tracker[source_ip]:
                del self.no_response_probe_tracker[source_ip]

    def dt_from_ts(self, ts):
        if isinstance(ts, float):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        return ts

if __name__ == '__main__':
    print("Starting detection engine test...")
    test_q = queue.Queue()
    stop_ev = threading.Event()
    test_alerts_list = []

    def mock_logger(scan_type, timestamp, source_ip, destination_ip, destination_port, protocol, details, source_port=None): # Added source_port
        alert_msg = (f"ALERT [{timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp}]: {scan_type} from {source_ip}"
                     f"{(':' + str(source_port)) if source_port else ''} to {destination_ip}:{destination_port} ({protocol}). Details: {details}")
        print(alert_msg)
        test_alerts_list.append(alert_msg)

    engine = DetectionEngine(test_q, mock_logger, stop_ev)
    engine.start()
    base_time = datetime.now(timezone.utc)

    # Test SYN Scan (High Rate to Port)
    syn_scan_source = '10.0.0.1'
    syn_scan_dest_ip = '192.168.1.100'
    syn_scan_dest_port = 80
    print(f"\n--- Test: SYN Scan (High Rate to Port) from {syn_scan_source} to {syn_scan_dest_ip}:{syn_scan_dest_port} ---")
    for i in range(engine.SYN_SCAN_THRESHOLD_COUNT): # Send exactly threshold count
        pkt = {
            'timestamp': (base_time + timedelta(milliseconds=i * 100)).isoformat(),
            'source_ip': syn_scan_source, 'destination_ip': syn_scan_dest_ip, 
            'destination_port': syn_scan_dest_port, 'source_port': 1000+i, 'protocol': 'TCP', 
            'flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        }
        print(f"Putting packet: {pkt}")
        test_q.put(pkt)
        time.sleep(0.01) # Small delay to allow processing

    # Test SYN Scan (Multiple Ports on Dest)
    multi_port_source = '10.0.0.2'
    multi_port_dest = '192.168.1.101'
    print(f"\n--- Test: SYN Scan (Multiple Ports on Dest) from {multi_port_source} to {multi_port_dest} ---")
    for i in range(engine.SYN_SCAN_TARGET_PORT_THRESHOLD):
        pkt = {
            'timestamp': (base_time + timedelta(seconds=1, milliseconds=i * 100)).isoformat(),
            'source_ip': multi_port_source, 'destination_ip': multi_port_dest,
            'destination_port': 8000 + i, 'source_port': 2000+i, 'protocol': 'TCP',
            'flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        }
        print(f"Putting packet: {pkt}")
        test_q.put(pkt)
        time.sleep(0.01)

    # Test No Response Scan
    no_response_source = '10.0.0.4'
    print(f"\n--- Test: No Response Scan from {no_response_source} ---")
    # Send probes that won't be answered
    for i in range(engine.NO_RESPONSE_SCAN_THRESHOLD_COUNT):
        pkt = {
            'timestamp': (base_time + timedelta(seconds=2, milliseconds=i * 30)).isoformat(),
            'source_ip': no_response_source, 'destination_ip': f'172.16.0.{i+1}',
            'destination_port': 3000 + i, 'source_port': 3000+i, 'protocol': 'TCP',
            'flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        }
        print(f"Putting No-Response probe: {pkt}")
        test_q.put(pkt)
        time.sleep(0.01)
    
    # Add a dummy packet for the no_response_source to trigger its check after timeout period
    dummy_packet_time = base_time + timedelta(seconds=2 + engine.NO_RESPONSE_PROBE_TIMEOUT_SECONDS + 1)
    dummy_pkt = {
        'timestamp': dummy_packet_time.isoformat(),
        'source_ip': no_response_source, 'destination_ip': '1.2.3.4', 
        'destination_port': 1234, 'source_port': 1234, 'protocol': 'TCP', 
        'flags': {'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
    }
    print(f"Putting dummy packet to trigger No-Response check: {dummy_pkt}")
    test_q.put(dummy_pkt)


    print(f"\n--- All test packets sent. Waiting for processing (approx {engine.NO_RESPONSE_PROBE_TIMEOUT_SECONDS + 5}s)... ---")
    time.sleep(engine.NO_RESPONSE_PROBE_TIMEOUT_SECONDS + 5) # Wait for No Response timeout and processing

    print("\n--- Stopping engine... ---")
    stop_ev.set()
    engine.join(timeout=10)

    if engine.is_alive(): print("Engine thread did not join cleanly!")
    else: print("Engine thread joined.")
    
    print(f"\n--- Detection engine test finished. Total alerts generated: {len(test_alerts_list)} ---")
    for alert_content in test_alerts_list:
        print(alert_content)

    # Basic assertions (can be made more specific)
    assert any("SYN Scan (High Rate to Port) from 10.0.0.1" in alert for alert in test_alerts_list), "Missing SYN High Rate alert"
    assert any("SYN Scan (Multiple Ports on Dest) from 10.0.0.2" in alert for alert in test_alerts_list), "Missing SYN Multi-Port alert"
    assert any("No Response Scan from 10.0.0.4" in alert for alert in test_alerts_list), "Missing No Response Scan alert"
    print("\nBasic alert validation passed if assertions did not fail.")
