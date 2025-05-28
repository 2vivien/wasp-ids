import json
from datetime import datetime, timezone, timedelta
import sys # For example usage and printing

# --- Configuration for Detection Logic ---
# SYN Scan Detection
SYN_SCAN_WINDOW_SECONDS = 60  # Time window to track SYN packets from a source
SYN_SCAN_THRESHOLD_COUNT = 10 # Number of unacknowledged SYNs from one source to trigger alert
SYN_SCAN_CLEANUP_AGE_SECONDS = SYN_SCAN_WINDOW_SECONDS * 2 # How long to keep SYN scan entries

# Horizontal Scan Detection (Port Scanning across multiple IPs, or many ports on one IP)
# For this implementation, we'll focus on one source IP hitting many destination ports.
HORIZONTAL_SCAN_WINDOW_SECONDS = 60
HORIZONTAL_SCAN_PORT_THRESHOLD = 10 # Number of unique destination ports hit by one source
HORIZONTAL_SCAN_CLEANUP_AGE_SECONDS = HORIZONTAL_SCAN_WINDOW_SECONDS * 2

# Port Sweep Detection (Scanning multiple ports on a single destination IP from a source)
PORT_SWEEP_WINDOW_SECONDS = 60
PORT_SWEEP_THRESHOLD = 10 # Number of unique destination ports hit on one dest IP from one source
PORT_SWEEP_CLEANUP_AGE_SECONDS = PORT_SWEEP_WINDOW_SECONDS * 2

# General tracker cleanup
GENERAL_TRACKER_CLEANUP_INTERVAL_PACKETS = 100 # How often to run cleanup (e.g., every 100 packets)


class DetectionEngine:
    def __init__(self, config_path="anomaly_detection_config.json"):
        self.config_path = config_path
        self.anomaly_config = None
        self._load_config()

        # State Management Data Structures
        # For SYN Scan: {'src_ip': [{'ts': datetime, 'dst_ip': ip, 'dst_port': port, 'acked': False}, ...]}
        self.syn_scan_tracker = {}
        
        # For Horizontal Scan (Source IP -> many unique Destination Ports)
        # {'src_ip': {'ports_hit': {port1, port2}, 'timestamps': [ts1, ts2, ...]}}
        self.horizontal_scan_tracker = {}
        
        # For Port Sweep (Source IP -> specific Dest IP -> many unique Destination Ports)
        # {'src_ip_dst_ip_pair': {'ports_hit': {port1, port2}, 'timestamps': [ts1, ts2, ...]}}
        # where src_ip_dst_ip_pair is a tuple like (src_ip, dst_ip)
        self.port_sweep_tracker = {}

        self.packets_processed_since_last_cleanup = 0

    def _load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                self.anomaly_config = json.load(f)
            print(f"DetectionEngine: Anomaly detection configuration loaded from '{self.config_path}'.")
            print(f"DetectionEngine: Config content - MLJAR Results Path: {self.anomaly_config.get('mljar_results_path', 'Not specified')}")
        except FileNotFoundError:
            print(f"DetectionEngine: Warning - Anomaly detection config file '{self.config_path}' not found. Anomaly detection may be limited.")
            self.anomaly_config = {} # Ensure it's a dict
        except json.JSONDecodeError:
            print(f"DetectionEngine: Error - Could not decode JSON from '{self.config_path}'.")
            self.anomaly_config = {}
        except Exception as e:
            print(f"DetectionEngine: Error loading config '{self.config_path}': {e}")
            self.anomaly_config = {}

    def _cleanup_trackers(self):
        """
        Cleans up old entries from state trackers to prevent memory exhaustion.
        """
        now = datetime.now(timezone.utc)

        # Cleanup SYN Scan Tracker
        cleanup_time_syn = now - timedelta(seconds=SYN_SCAN_CLEANUP_AGE_SECONDS)
        for src_ip, entries in list(self.syn_scan_tracker.items()):
            self.syn_scan_tracker[src_ip] = [e for e in entries if e['ts'] > cleanup_time_syn]
            if not self.syn_scan_tracker[src_ip]:
                del self.syn_scan_tracker[src_ip]

        # Cleanup Horizontal Scan Tracker
        cleanup_time_horizontal = now - timedelta(seconds=HORIZONTAL_SCAN_CLEANUP_AGE_SECONDS)
        for src_ip, data in list(self.horizontal_scan_tracker.items()):
            data['timestamps'] = [ts for ts in data['timestamps'] if ts > cleanup_time_horizontal]
            # If timestamps are old, ports_hit might represent old activity.
            # A more robust cleanup might remove ports based on their individual timestamps if stored.
            # For now, if all associated timestamps are old, we clear ports_hit.
            if not data['timestamps']:
                 data['ports_hit'].clear() # Clear ports if no recent activity
            
            if not data['ports_hit'] and not data['timestamps']: # If both empty, remove entry
                del self.horizontal_scan_tracker[src_ip]


        # Cleanup Port Sweep Tracker
        cleanup_time_port_sweep = now - timedelta(seconds=PORT_SWEEP_CLEANUP_AGE_SECONDS)
        for pair_key, data in list(self.port_sweep_tracker.items()):
            data['timestamps'] = [ts for ts in data['timestamps'] if ts > cleanup_time_port_sweep]
            if not data['timestamps']:
                data['ports_hit'].clear()

            if not data['ports_hit'] and not data['timestamps']:
                del self.port_sweep_tracker[pair_key]
        
        # print("DetectionEngine: Trackers cleaned up.", file=sys.stderr)


    def _detect_syn_scan(self, packet_data: dict) -> dict | None:
        """
        Detects potential SYN scan activity.
        A SYN scan is characterized by a series of SYN packets from a single source
        to various ports on one or multiple destination IPs without corresponding ACKs.
        """
        src_ip = packet_data.get('source_ip')
        dst_ip = packet_data.get('destination_ip')
        dst_port = packet_data.get('destination_port')
        flags = packet_data.get('flags')
        protocol = packet_data.get('protocol')
        packet_timestamp = packet_data.get('timestamp')

        if not src_ip or protocol != 'TCP' or not packet_timestamp:
            return None

        now = datetime.now(timezone.utc) # Use current time for window evaluation

        # Manage SYN packets
        if 'S' in (flags or "") and 'A' not in (flags or ""): # Pure SYN
            if src_ip not in self.syn_scan_tracker:
                self.syn_scan_tracker[src_ip] = []
            
            self.syn_scan_tracker[src_ip].append({
                'ts': packet_timestamp, 
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'acked': False
            })

            # Check for scan
            unacked_syn_count = 0
            window_start_time = now - timedelta(seconds=SYN_SCAN_WINDOW_SECONDS)
            
            relevant_syns = [
                syn for syn in self.syn_scan_tracker[src_ip]
                if syn['ts'] >= window_start_time and not syn['acked']
            ]

            if len(relevant_syns) >= SYN_SCAN_THRESHOLD_COUNT:
                # To avoid repeated alerts for the same ongoing scan,
                # we could add a cooldown mechanism here (e.g., alert once per window per IP)
                # For now, basic alert generation:
                return {
                    "timestamp": packet_timestamp, # Timestamp of the packet that triggered detection
                    "source_ip": src_ip,
                    "destination_ip": dst_ip, # Could be generalized if scanning multiple IPs
                    "source_port": packet_data.get('source_port'),
                    "destination_port": dst_port,
                    "protocol": protocol,
                    "scan_type": "SYN Scan",
                    "severity": "Medium",
                    "details": f"Source IP {src_ip} sent {len(relevant_syns)} unacknowledged SYN packets within {SYN_SCAN_WINDOW_SECONDS}s."
                }
        
        # Manage ACKs (primarily SYN-ACKs)
        # This part is simplified: if we see an ACK from dst_ip/dst_port to src_ip/src_port that matches a sent SYN, mark it.
        # For true accuracy, we'd match TCP sequence/acknowledgment numbers.
        elif 'A' in (flags or ""):
            if dst_ip in self.syn_scan_tracker: # dst_ip of current packet is the src_ip of original SYN
                for syn_entry in self.syn_scan_tracker[dst_ip]:
                    if (syn_entry['dst_ip'] == src_ip and 
                        syn_entry['dst_port'] == packet_data.get('source_port') and # current packet's source port is original SYN's dest port
                        not syn_entry['acked']):
                        # Heuristic: If an ACK comes back, assume a SYN it was responding to is "acked"
                        # This is a simplification. A SYN-ACK ('SA') is a better indicator.
                        if 'S' in (flags or ""): # It's a SYN-ACK
                             syn_entry['acked'] = True
                        # If it's just an ACK, it might be part of an established connection or response.
                        # For simplicity, we only mark direct SYN-ACKs as "acked" for now.
                        break # Assume one ACK per SYN for simplicity
        return None

    def _detect_horizontal_scan(self, packet_data: dict) -> dict | None:
        """
        Detects potential Horizontal Port Scan activity from a source IP.
        Characterized by a single source IP sending SYN packets to many unique destination ports.
        """
        src_ip = packet_data.get('source_ip')
        dst_port = packet_data.get('destination_port')
        flags = packet_data.get('flags')
        protocol = packet_data.get('protocol')
        packet_timestamp = packet_data.get('timestamp')

        if not src_ip or not dst_port or protocol != 'TCP' or 'S' not in (flags or "") or not packet_timestamp:
            return None

        now = datetime.now(timezone.utc)
        window_start_time = now - timedelta(seconds=HORIZONTAL_SCAN_WINDOW_SECONDS)

        if src_ip not in self.horizontal_scan_tracker:
            self.horizontal_scan_tracker[src_ip] = {'ports_hit': set(), 'timestamps': []}
        
        tracker = self.horizontal_scan_tracker[src_ip]
        tracker['ports_hit'].add(dst_port)
        tracker['timestamps'].append(packet_timestamp)
        
        # Filter timestamps and corresponding ports for the current window
        # This is a simplification: we count unique ports hit corresponding to *any* SYN in the window
        recent_timestamps = [ts for ts in tracker['timestamps'] if ts >= window_start_time]
        tracker['timestamps'] = recent_timestamps # Keep only recent timestamps

        # The set `ports_hit` is cumulative until cleaned. For alert, consider ports hit recently.
        # A more accurate way would be to store (port, timestamp) pairs.
        # For now, if there are recent SYNs, check the size of the cumulative set of ports.
        if recent_timestamps and len(tracker['ports_hit']) >= HORIZONTAL_SCAN_PORT_THRESHOLD:
            # To avoid re-alerting, one might add a cooldown or check if an alert for this scan is already active.
            return {
                "timestamp": packet_timestamp,
                "source_ip": src_ip,
                "destination_ip": packet_data.get('destination_ip'), # Included for context
                "source_port": packet_data.get('source_port'),
                "destination_port": None, # Alert is for multiple ports
                "protocol": protocol,
                "scan_type": "Horizontal Scan (Port Scan)",
                "severity": "Medium",
                "details": f"Source IP {src_ip} scanned {len(tracker['ports_hit'])} unique ports within {HORIZONTAL_SCAN_WINDOW_SECONDS}s."
            }
        return None

    def _detect_port_sweep(self, packet_data: dict) -> dict | None:
        """
        Detects potential Port Sweep activity (one source to one destination, many ports).
        """
        src_ip = packet_data.get('source_ip')
        dst_ip = packet_data.get('destination_ip')
        dst_port = packet_data.get('destination_port')
        flags = packet_data.get('flags')
        protocol = packet_data.get('protocol')
        packet_timestamp = packet_data.get('timestamp')

        # Primarily for TCP SYN packets, but can be adapted for UDP if ICMP unreachables are processed.
        if not src_ip or not dst_ip or not dst_port or protocol != 'TCP' or 'S' not in (flags or "") or not packet_timestamp:
            return None

        now = datetime.now(timezone.utc)
        window_start_time = now - timedelta(seconds=PORT_SWEEP_WINDOW_SECONDS)
        pair_key = (src_ip, dst_ip)

        if pair_key not in self.port_sweep_tracker:
            self.port_sweep_tracker[pair_key] = {'ports_hit': set(), 'timestamps': []}

        tracker = self.port_sweep_tracker[pair_key]
        tracker['ports_hit'].add(dst_port)
        tracker['timestamps'].append(packet_timestamp)

        recent_timestamps = [ts for ts in tracker['timestamps'] if ts >= window_start_time]
        tracker['timestamps'] = recent_timestamps

        if recent_timestamps and len(tracker['ports_hit']) >= PORT_SWEEP_THRESHOLD:
            return {
                "timestamp": packet_timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": packet_data.get('source_port'),
                "destination_port": None, # Alert is for multiple ports on the destination
                "protocol": protocol,
                "scan_type": "Port Sweep",
                "severity": "Medium",
                "details": f"Source IP {src_ip} swept {len(tracker['ports_hit'])} unique ports on {dst_ip} within {PORT_SWEEP_WINDOW_SECONDS}s."
            }
        return None

    def _detect_anomalies(self, packet_data: dict) -> list:
        """
        Placeholder for anomaly-based detection using ML models or statistical methods.
        """
        # This is where logic based on MLJAR-derived thresholds/models would go.
        # For example, one might extract features from packet_data similar to training_data.csv,
        # then use the loaded model (from self.anomaly_config['mljar_results_path']) to predict.
        # Or, apply statistical thresholds derived during training.
        if self.anomaly_config:
            # print(f"DetectionEngine: Anomaly detection check for packet. Config: {self.anomaly_config.get('mljar_results_path')}", file=sys.stderr)
            pass # No actual detection logic yet
        return []


    def process_packet(self, packet_data: dict) -> list:
        """
        Processes a single packet and returns a list of alerts.
        """
        alerts = []
        if not isinstance(packet_data, dict): # Ensure packet_data is a dictionary
            return alerts

        # Periodically cleanup trackers
        self.packets_processed_since_last_cleanup += 1
        if self.packets_processed_since_last_cleanup >= GENERAL_TRACKER_CLEANUP_INTERVAL_PACKETS:
            self._cleanup_trackers()
            self.packets_processed_since_last_cleanup = 0

        # Signature-based detection
        syn_scan_alert = self._detect_syn_scan(packet_data)
        if syn_scan_alert:
            alerts.append(syn_scan_alert)
        
        horizontal_scan_alert = self._detect_horizontal_scan(packet_data)
        if horizontal_scan_alert:
            # Avoid duplicate alerts if a SYN scan also qualifies as a horizontal scan
            # This simple check might not be enough for complex overlaps
            is_duplicate = False
            for alert in alerts:
                if alert["scan_type"] == "SYN Scan" and alert["source_ip"] == horizontal_scan_alert["source_ip"]:
                    is_duplicate = True
                    break
            if not is_duplicate:
                 alerts.append(horizontal_scan_alert)

        port_sweep_alert = self._detect_port_sweep(packet_data)
        if port_sweep_alert:
            alerts.append(port_sweep_alert)

        # Anomaly-based detection (placeholder)
        anomaly_alerts = self._detect_anomalies(packet_data)
        alerts.extend(anomaly_alerts)

        return alerts

if __name__ == '__main__':
    print("Starting DetectionEngine example usage...", file=sys.stderr)
    engine = DetectionEngine()

    # --- Test Data Generation ---
    base_ts = datetime.now(timezone.utc)

    def create_packet(src_ip, dst_ip, dst_port, flags, protocol="TCP", ts_offset_micros=0, src_port=None):
        if src_port is None: # Assign a pseudo-random source port if none given
            src_port = 10000 + (dst_port % 1000) 
        return {
            "timestamp": base_ts + timedelta(microseconds=ts_offset_micros),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "flags": flags
        }

    sample_packets = []

    # 1. Normal Traffic
    sample_packets.append(create_packet("192.168.1.10", "192.168.1.20", 80, "S", ts_offset_micros=100))
    sample_packets.append(create_packet("192.168.1.20", "192.168.1.10", 80, "SA", src_port=80, ts_offset_micros=200)) # SYN-ACK
    sample_packets.append(create_packet("192.168.1.10", "192.168.1.20", 80, "A", ts_offset_micros=300))
    sample_packets.append(create_packet("10.0.0.1", "10.0.0.2", 443, "S", ts_offset_micros=400))
    sample_packets.append(create_packet("10.0.0.2", "10.0.0.1", 443, "SA", src_port=443, ts_offset_micros=500))
    sample_packets.append(create_packet("10.0.0.1", "10.0.0.2", 443, "A", ts_offset_micros=600))


    # 2. SYN Scan Simulation (Attacker: 1.1.1.1)
    # Exceeds SYN_SCAN_THRESHOLD_COUNT (10)
    syn_scan_attacker = "1.1.1.1"
    for i in range(SYN_SCAN_THRESHOLD_COUNT + 5):
        sample_packets.append(create_packet(syn_scan_attacker, f"192.168.1.{20+i}", 1000+i, "S", ts_offset_micros=10000 + i*100))
    
    # Add one SYN-ACK to test acked logic (won't stop alert if threshold already met by unacked)
    sample_packets.append(create_packet(f"192.168.1.20", syn_scan_attacker, 1000, "SA", src_port=1000, ts_offset_micros=10000 + 0*100 + 50))


    # 3. Horizontal Scan Simulation (Attacker: 2.2.2.2)
    # Exceeds HORIZONTAL_SCAN_PORT_THRESHOLD (10)
    horizontal_scan_attacker = "2.2.2.2"
    for i in range(HORIZONTAL_SCAN_PORT_THRESHOLD + 5):
        # Hits different ports on potentially different IPs (though here on same for simplicity)
        sample_packets.append(create_packet(horizontal_scan_attacker, "192.168.2.10", 2000+i, "S", ts_offset_micros=20000 + i*100))

    # 4. Port Sweep Simulation (Attacker: 3.3.3.3, Victim: 192.168.3.30)
    # Exceeds PORT_SWEEP_THRESHOLD (10)
    port_sweep_attacker = "3.3.3.3"
    port_sweep_victim = "192.168.3.30"
    for i in range(PORT_SWEEP_THRESHOLD + 5):
        sample_packets.append(create_packet(port_sweep_attacker, port_sweep_victim, 3000+i, "S", ts_offset_micros=30000 + i*100))

    # 5. ARP packet (example)
    sample_packets.append({
            "timestamp": base_ts + timedelta(microseconds=40000),
            "source_ip": "192.168.1.100", # Sender MAC address is usually here in real tcpdump
            "destination_ip": "Broadcast", # Target MAC is Broadcast
            "source_port": None,
            "destination_port": None,
            "protocol": "ARP",
            "flags": None,
            "details" : "who-has 192.168.1.1 tell 192.168.1.100" # Simplified detail
        })


    print(f"\n--- Processing {len(sample_packets)} Sample Packets ---", file=sys.stderr)
    total_alerts = 0
    for i, packet in enumerate(sample_packets):
        # print(f"\nProcessing packet {i+1}: {packet}", file=sys.stderr)
        alerts = engine.process_packet(packet)
        if alerts:
            total_alerts += len(alerts)
            for alert in alerts:
                print(f"ALERT Generated: {alert}", file=sys.stderr)
    
    print(f"\n--- Example Usage Complete. Total alerts: {total_alerts} ---", file=sys.stderr)

    # Test cleanup explicitly after processing (normally called periodically)
    print("\n--- Explicitly calling cleanup for demonstration ---", file=sys.stderr)
    engine._cleanup_trackers()
    print("SYN Scan Tracker after cleanup:", engine.syn_scan_tracker, file=sys.stderr)
    print("Horizontal Scan Tracker after cleanup:", engine.horizontal_scan_tracker, file=sys.stderr)
    print("Port Sweep Tracker after cleanup:", engine.port_sweep_tracker, file=sys.stderr)

    # Create a dummy anomaly_detection_config.json if it doesn't exist for testing
    import os
    if not os.path.exists("anomaly_detection_config.json"):
        print("\nCreating dummy 'anomaly_detection_config.json' for next run...", file=sys.stderr)
        with open("anomaly_detection_config.json", "w") as f:
            json.dump({
                "training_timestamp_utc": "2023-01-01T00:00:00+00:00",
                "mljar_results_path": "/path/to/dummy/mljar_results",
                "feature_importances": {"feature1": 0.5, "feature2": 0.3}
            }, f, indent=4)

# (Placeholder for detection_engine.py) - Removed
# (Placeholder for log_manager.py) - Removed
# This file will house the intrusion detection engine. - Retained
# It will use the trained ML models to analyze packet data and identify threats. - Retained
# Further details will be added as the project progresses. - Retained
