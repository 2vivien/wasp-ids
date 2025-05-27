import threading
import time
import queue
from collections import defaultdict
from datetime import datetime, timedelta, timezone

class DetectionEngine(threading.Thread):
    """
    A thread that processes network packet data from a queue, applies detection rules,
    and triggers alerts via a callback function.
    """
    def __init__(self, input_queue, log_alert_callback, stop_event=None):
        super().__init__()
        self.input_queue = input_queue               # queue.Queue to receive packet data (dictionaries)
        self.log_alert_callback = log_alert_callback # Function to call when an alert is triggered
        self.stop_event = stop_event or threading.Event() # threading.Event to signal thread termination
        self.setName("DetectionEngineThread")        # Name for easier debugging
        self.last_no_response_cleanup_time = datetime.now(timezone.utc)

        # --- Rule Parameters ---
        # These define the thresholds and time windows for various detection rules.
        # They are currently hardcoded but could be made configurable (e.g., from a config file or UI).

        # SYN Scan (High Rate to Single Port) Parameters:
        self.SYN_SCAN_THRESHOLD_COUNT = 30       # Augmenté de 15 à 30 (30 SYNs vers un même port)
        self.SYN_SCAN_TIME_WINDOW_SECONDS = 10   # Garde la même fenêtre temporelle (10s)

        # SYN Scan (Multiple Ports on a Single Destination) Parameters:
        self.SYN_SCAN_TARGET_PORT_THRESHOLD = 10 # Augmenté de 5 à 10 (10 ports distincts sur une même IP)
        self.SYN_SCAN_TARGET_TIME_WINDOW = 30    # Nouveau: fenêtre de 30s pour le multi-port

        # Horizontal Scan Parameters:
        self.HORIZONTAL_SCAN_PORT_THRESHOLD = 25 # Augmenté de 15 à 25 (25 cibles IP:port différentes)
        self.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS = 60 # Étendu de 30s à 60s

        # No Response Scan Parameters:
        self.NO_RESPONSE_PROBE_TIMEOUT_SECONDS = 10 # Augmenté de 5s à 10s (temps d'attente réponse)
        self.NO_RESPONSE_SCAN_THRESHOLD_COUNT = 15  # Augmenté de 10 à 15 (15 probes sans réponse)

        # --- State Trackers ---
        # These dictionaries store state information required for rule evaluation.
        # They use defaultdict for convenience in creating nested structures.

        # For SYN Scan (High Rate to Port):
        # Tracks SYNs from a source IP to a specific destination IP and port.
        # Structure: {source_ip: {dest_ip: {dest_port: [timestamp1, timestamp2, ...]}}}
        self.syn_from_source_to_dest_port_tracker = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        
        # For SYN Scan (Multiple Ports on Dest):
        # Tracks distinct ports targeted by a source IP on a single destination IP.
        # Structure: {source_ip: {dest_ip: {port1, port2, ...}}}
        self.syn_from_source_to_dest_ip_tracker = defaultdict(lambda: defaultdict(set))
        
        # For Horizontal Scans:
        # Tracks distinct (dest_ip, dest_port) tuples targeted by a source IP.
        # Structure: {source_ip: {'targets': {(dest_ip1, port1), (dest_ip2, port2), ...}, 'first_syn_time': datetime}}
        self.horizontal_scan_tracker = defaultdict(lambda: {'targets': set(), 'first_syn_time': None})

        # For No-Response Scans:
        # Tracks outgoing probes (SYNs) and whether they received a response.
        # Structure: {scanner_ip: {target_ip: {target_port: {'timestamp': probe_time, 'responded': False}}}}
        self.no_response_probe_tracker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {'timestamp': None, 'responded': False})))
        # Tracks sources that have recently triggered a "No Response Scan" to implement a cooldown period.
        # Structure: {source_ip: alert_timestamp}
        self.no_response_alerted_sources = {} 
        self.last_no_response_cleanup_time = datetime.now(timezone.utc) # Timestamp of the last global cleanup

    def _prune_timestamps(self, timestamp_list, window_seconds, now=None):
        """
        Helper function to remove timestamps older than the specified window from a list.
        Args:
            timestamp_list (list): A list of datetime objects.
            window_seconds (int): The time window in seconds.
            now (datetime, optional): The current time. Defaults to datetime.now().
        Returns:
            list: A new list containing only timestamps within the window.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = now.astimezone(timezone.utc) - timedelta(seconds=window_seconds)
        return [ts for ts in timestamp_list if ts > cutoff]

    def _prune_syn_from_source_to_dest_ip_tracker(self, now):
        """
        Prunes the tracker for SYN scans to multiple ports on a single destination.
        Currently, this tracker is cleared upon alert. More sophisticated time-based pruning
        could be added (e.g., if a source_ip hasn't sent any SYNs for a while, its entries could be removed).
        This is a placeholder for more advanced pruning logic.
        """
        # This tracker (self.syn_from_source_to_dest_ip_tracker) is currently cleared when an alert is triggered.
        # For more robust pruning, one might track the last activity time for each source_ip
        # and remove entries that have been inactive for an extended period.
        # Example (conceptual):
        # for source_ip, dest_data in list(self.syn_from_source_to_dest_ip_tracker.items()):
        #     if is_inactive(source_ip, now, some_long_timeout): # is_inactive would be a new helper
        #         del self.syn_from_source_to_dest_ip_tracker[source_ip]
        pass # Currently cleared on alert, so explicit pruning here is minimal.

    def _prune_horizontal_scan_tracker(self, now):
        """
        Prunes old entries from the horizontal_scan_tracker.
        If a source IP's 'first_syn_time' (start of its current scan window) is older 
        than a multiple of the HORIZONTAL_SCAN_TIME_WINDOW_SECONDS, its entry is removed.
        This prevents indefinite growth of the tracker for inactive sources.
        """
        # Iterate over a copy of items for safe deletion from the dictionary during iteration.
        for source_ip, data in list(self.horizontal_scan_tracker.items()):
            # If the first SYN for this source is older than (window * 2), remove the entry.
            # The multiplier (e.g., 2) provides a grace period beyond the active window.
            if data['first_syn_time'] and \
               (now - data['first_syn_time'].replace(tzinfo=timezone.utc)).total_seconds() > self.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS * 2:
                del self.horizontal_scan_tracker[source_ip]

    def _prune_no_response_probe_tracker(self, now):
        """
        Prunes very old entries from no_response_probe_tracker to manage memory.
        This includes individual probe entries and entire source IP entries if inactive.
        Also prunes sources from the alert cooldown list (no_response_alerted_sources)
        after a sufficient period has passed.
        """
        # Define a longer timeout for cleaning up entire entries from the probe tracker.
        # This ensures that probes are kept for a reasonable time beyond the alert timeout,
        # useful for potential future analysis or correlation, but not indefinitely.
        timeout_for_full_entry_cleanup = self.NO_RESPONSE_PROBE_TIMEOUT_SECONDS * 10 

        # Iterate over a copy of items for safe deletion.
        for src_ip, dest_ips in list(self.no_response_probe_tracker.items()):
            for d_ip, ports in list(dest_ips.items()):
                for d_port, status in list(ports.items()):
                    # If a probe's timestamp is older than the cleanup timeout, remove it.
                    if status['timestamp'] and (now - status['timestamp']).total_seconds() > timeout_for_full_entry_cleanup:
                        del self.no_response_probe_tracker[src_ip][d_ip][d_port]
                if not self.no_response_probe_tracker[src_ip][d_ip]: # If no ports left for this dest_ip under src_ip
                    del self.no_response_probe_tracker[src_ip][d_ip]
            if not self.no_response_probe_tracker[src_ip]: # If no dest_ips left for this src_ip
                del self.no_response_probe_tracker[src_ip]
        
        # Prune sources from the no-response alert cooldown list.
        # The cooldown is typically longer than the scan detection window to prevent rapid re-alerting.
        # Example: Use HORIZONTAL_SCAN_TIME_WINDOW_SECONDS * 4 as a cooldown duration.
        cooldown_duration = self.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS * 4 
        for src_ip, alert_time in list(self.no_response_alerted_sources.items()):
            if (now - alert_time).total_seconds() > cooldown_duration:
                del self.no_response_alerted_sources[src_ip]

    def periodic_cleanup(self, now):
        """
        Performs periodic cleanup of all relevant state trackers.
        This is called during the main run loop if the input queue is empty,
        and also during the processing of each packet if a longer interval has passed.
        Args:
            now (datetime): The current time, passed to ensure consistency across pruning operations.
        """
        # print(f"[{now}] DetectionEngine: Running periodic cleanup...") # Uncomment for debugging
        self._prune_syn_from_source_to_dest_ip_tracker(now) # Currently a pass, relies on alert-based clearing.
        self._prune_horizontal_scan_tracker(now)
        self._prune_no_response_probe_tracker(now)
        self.last_no_response_cleanup_time = now # Update the timestamp of the last cleanup.


    def process_packet(self, packet_data):
        """
        Processes a single packet, updates state trackers, and checks detection rules.
        Args:
            packet_data (dict): A dictionary containing parsed packet information,
                                expected to conform to PacketData.to_dict() format.
        """
        if not packet_data or not isinstance(packet_data, dict):
            return

        print(f"--- [DetectionEngine] Received packet_data: {packet_data}")

        current_time = datetime.now(timezone.utc) # Use a consistent "now" for this processing cycle
        
        try:
            # ids_capture.py produces ISO string with 'Z' like '2023-10-27T10:20:30.123456Z'
            # Python's fromisoformat handles 'Z' correctly from 3.11+.
            # For broader compatibility, replace 'Z' with '+00:00'.
            timestamp_str = packet_data.get("timestamp")
            if timestamp_str:
                if timestamp_str.endswith('Z'):
                    timestamp = datetime.fromisoformat(timestamp_str[:-1] + "+00:00").replace(tzinfo=timezone.utc)
                else:
                    timestamp = datetime.fromisoformat(timestamp_str).replace(tzinfo=timezone.utc)
            else:
                timestamp = current_time
        except (ValueError, TypeError) as e:
            timestamp = current_time
            return # Packet data is invalid, skip processing

        current_time = datetime.now(timezone.utc) # Use a consistent "now" for this processing cycle
        
        # Parse timestamp from packet_data. Timestamps from ids_capture are ISO strings.
        try:
            timestamp_str = packet_data.get("timestamp")
            if timestamp_str:
                 if timestamp_str.endswith('Z'): # Handle 'Z' for UTC
                    timestamp_str = timestamp_str[:-1] + "+00:00"
                 timestamp = datetime.fromisoformat(timestamp_str)
            else: # Fallback if timestamp is missing (should not happen with valid PacketData)
                timestamp = current_time
        except (ValueError, TypeError) as e:
            # print(f"Error parsing timestamp: {packet_data.get('timestamp')}, error: {e}. Using current_time.")
            timestamp = current_time # Fallback to current time if parsing fails

        # Extract core packet information
        source_ip = packet_data.get("source_ip")
        dest_ip = packet_data.get("destination_ip")
        dest_port = packet_data.get("destination_port") # Can be string for ICMP, or int
        protocol = packet_data.get("protocol")
        flags = packet_data.get("flags", {}) # TCP flags like {'SYN': True}
        print(f"--- [DetectionEngine] Extracted flags: {flags}")

        # Basic validation of extracted fields
        if not source_ip or not dest_ip or not protocol:
            return # Essential information missing

        # Common dictionary for alert logging parameters
        log_common = {
            "timestamp": timestamp, # Use the parsed (or fallback) packet timestamp for the alert
            "source_ip": source_ip, "destination_ip": dest_ip, 
            "protocol": protocol,
        }

        # --- Rule Logic: Process based on protocol ---
        if protocol == "TCP":
            # Determine specific TCP flags for easier rule logic
            is_syn = flags.get("SYN", False) and not flags.get("ACK", False) and \
                     not flags.get("RST", False) and not flags.get("FIN", False)
            is_syn_ack = flags.get("SYN", False) and flags.get("ACK", False)
            is_rst = flags.get("RST", False)
            print(f"--- [DetectionEngine] Calculated boolean flags: is_syn={is_syn}, is_syn_ack={is_syn_ack}, is_rst={is_rst}")

            if is_syn: # --- Processing for SYN packets ---
                # Rule: SYN Scan (High rate of SYNs to a specific destination port)
                # Detects if a source sends many SYN packets to a single destination IP:port
                # within self.SYN_SCAN_TIME_WINDOW_SECONDS.
                syns_to_specific_port = self.syn_from_source_to_dest_port_tracker[source_ip][dest_ip][dest_port]
                syns_to_specific_port.append(timestamp) # Record current SYN's timestamp
                # Prune old timestamps from this specific list to keep it within the time window.
                syns_to_specific_port = self._prune_timestamps(syns_to_specific_port, self.SYN_SCAN_TIME_WINDOW_SECONDS, now=current_time)
                self.syn_from_source_to_dest_port_tracker[source_ip][dest_ip][dest_port] = syns_to_specific_port
                
                if len(syns_to_specific_port) >= self.SYN_SCAN_THRESHOLD_COUNT:
                    self.log_alert_callback(scan_type="SYN Scan (High Rate to Port)", **log_common,
                                            details=f"{source_ip} sent {len(syns_to_specific_port)} SYNs to {dest_ip}:{dest_port} in last {self.SYN_SCAN_TIME_WINDOW_SECONDS}s.")
                    # Clear after alert to prevent immediate re-alerting for the same burst.
                    self.syn_from_source_to_dest_port_tracker[source_ip][dest_ip][dest_port] = [] 

                # Rule: SYN Scan (SYNs to multiple distinct ports on a single destination IP)
                # Detects if a source sends SYNs to many different ports on the same destination host.
                # This rule counts unique ports targeted by a source on a destination IP.
                # It doesn't have a strict time window for each port addition to the set but relies on
                # overall activity and periodic pruning for cleanup.
                ports_targeted_on_dest_ip = self.syn_from_source_to_dest_ip_tracker[source_ip][dest_ip]
                ports_targeted_on_dest_ip.add(dest_port) # Add the current destination port to the set
                
                if len(ports_targeted_on_dest_ip) >= self.SYN_SCAN_TARGET_PORT_THRESHOLD:
                     self.log_alert_callback(scan_type="SYN Scan (Multiple Ports on Dest)", **log_common,
                                            destination_port="Multiple", # Port is variable for this alert type
                                            details=f"{source_ip} sent SYNs to {len(ports_targeted_on_dest_ip)} distinct ports on {dest_ip}.")
                     self.syn_from_source_to_dest_ip_tracker[source_ip][dest_ip].clear() # Clear after alert

                # Rule: Horizontal Scan (SYNs to many distinct destination IP:ports)
                # Detects if a source sends SYNs to many different destination IP addresses and ports.
                h_scan_data = self.horizontal_scan_tracker[source_ip]
                # Reset target set if the time window has passed since the first SYN of the current batch,
                # or if this is the first SYN recorded for this source.
                if h_scan_data['first_syn_time'] is None or \
                   (current_time - h_scan_data['first_syn_time']).total_seconds() > self.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS:
                    h_scan_data['targets'].clear() # Clear old targets
                    h_scan_data['first_syn_time'] = current_time # Start a new time window

                h_scan_data['targets'].add((dest_ip, dest_port)) # Add current (dest_ip, dest_port) tuple
                
                if len(h_scan_data['targets']) >= self.HORIZONTAL_SCAN_PORT_THRESHOLD:
                    self.log_alert_callback(scan_type="Horizontal Scan", timestamp=timestamp, source_ip=source_ip, protocol=protocol,
                                            destination_ip="Multiple", destination_port="Multiple", # Target is variable
                                            details=f"{source_ip} sent SYNs to {len(h_scan_data['targets'])} different IP:ports in last {self.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS}s.")
                    h_scan_data['targets'].clear() # Clear after alert
                    h_scan_data['first_syn_time'] = None # Reset window timing


                # Rule: No-Response Scan - Log this SYN as an outgoing probe
                # This part records any outgoing SYN packet in the no_response_probe_tracker.
                # The 'responded' flag is initially False and will be set to True if a SYN-ACK or RST is seen.
                self.no_response_probe_tracker[source_ip][dest_ip][dest_port]['timestamp'] = timestamp
                self.no_response_probe_tracker[source_ip][dest_ip][dest_port]['responded'] = False

            # --- Processing for SYN-ACK or RST packets (relevant for No-Response Scan) ---
            # If this packet is a SYN-ACK or RST, it might be a response to a probe previously sent.
            # In this case, packet_data's source_ip is the host that *sent* the SYN-ACK/RST (original target),
            # and dest_ip is the host that *received* it (original scanner).
            elif is_syn_ack or is_rst:
                original_scanner_ip = dest_ip  # The recipient of the SYN-ACK/RST was the original prober
                probed_host_ip = source_ip     # The sender of SYN-ACK/RST was the probed host
                probed_port = packet_data.get("source_port") # The port on the probed host that sent the response

                # Check if this response corresponds to a known probe in our tracker
                if original_scanner_ip in self.no_response_probe_tracker and \
                   probed_host_ip in self.no_response_probe_tracker[original_scanner_ip] and \
                   probed_port in self.no_response_probe_tracker[original_scanner_ip][probed_host_ip]:
                    # Mark the probe as 'responded' = True
                    self.no_response_probe_tracker[original_scanner_ip][probed_host_ip][probed_port]['responded'] = True


        # Rule: No Response Scan Check (triggered for the source_ip of the current packet)
        # This part checks if the *current packet's source IP* (which might be a scanner)
        # has made many probes that timed out (i.e., did not receive a SYN-ACK or RST).
        # This check is performed for any packet from a source IP that has previously sent probes.
        
        # Check if source_ip is in cooldown for no-response alerts to prevent alert flooding.
        cooldown_active = False
        if source_ip in self.no_response_alerted_sources:
            # Cooldown duration can be, e.g., twice the horizontal scan window.
            if (current_time - self.no_response_alerted_sources[source_ip]).total_seconds() < (self.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS * 2):
                cooldown_active = True
        
        if not cooldown_active and source_ip in self.no_response_probe_tracker: # Only proceed if this source_ip has made probes
            unanswered_probes_count = 0
            probed_targets_details = [] # For collecting example targets for the alert message
            
            # Iterate over probes sent by this source_ip.
            # Using list() for safe deletion during iteration if needed, though direct deletion is avoided here for clarity.
            for d_ip, ports in list(self.no_response_probe_tracker[source_ip].items()):
                for d_port, status in list(ports.items()):
                    if status['timestamp'] and not status['responded']:
                        # If a probe is older than the NO_RESPONSE_PROBE_TIMEOUT_SECONDS and hasn't received a response
                        if (current_time - status['timestamp']).total_seconds() > self.NO_RESPONSE_PROBE_TIMEOUT_SECONDS:
                            unanswered_probes_count += 1
                            if len(probed_targets_details) < 5: # Collect a few examples for the alert details
                                probed_targets_details.append(f"{d_ip}:{d_port}")
                    
                    # Optional: Aggressive cleanup of very old probes from this specific source's tracker.
                    # This is different from the global periodic_cleanup and focuses on the active source_ip.
                    # This helps manage memory for very active (but not necessarily malicious) scanners.
                    if status['timestamp'] and \
                       (current_time - status['timestamp']).total_seconds() > (self.NO_RESPONSE_PROBE_TIMEOUT_SECONDS * 5): # e.g., 5x timeout period
                        try:
                            del self.no_response_probe_tracker[source_ip][d_ip][d_port]
                        except KeyError: pass # Item might have been removed by another path (e.g. periodic_cleanup)
            
            if unanswered_probes_count >= self.NO_RESPONSE_SCAN_THRESHOLD_COUNT:
                self.log_alert_callback(scan_type="No Response Scan", timestamp=timestamp, source_ip=source_ip, protocol="TCP/UDP", # Protocol is generic as probes could be various types
                                        destination_ip="Multiple", destination_port="Multiple", # Targets are variable
                                        details=f"{source_ip} has >{self.NO_RESPONSE_SCAN_THRESHOLD_COUNT} probes to IP:ports without response after {self.NO_RESPONSE_PROBE_TIMEOUT_SECONDS}s. Example targets: {', '.join(probed_targets_details)}...")
                self.no_response_alerted_sources[source_ip] = current_time # Start cooldown for this source to prevent alert spam
                # Note: We don't clear all probes for this source from no_response_probe_tracker here.
                # The cooldown (no_response_alerted_sources) is the primary mechanism to prevent immediate re-alerting.
                # Individual timed-out probes are counted; new probes will continue to be tracked.

        # --- Periodic Global Cleanup ---
        # Perform a global cleanup of all trackers if enough time has passed since the last one.
        # This is important for managing memory over long run times, especially for less active sources
        # that wouldn't trigger cleanups within their specific rule logic.
        # The cleanup interval is set to 60 seconds.
        if (current_time - self.last_no_response_cleanup_time).total_seconds() > 60: 
            self.periodic_cleanup(current_time)


    def run(self):
        """Main execution method for the DetectionEngine thread."""
        print(f"{self.getName()} starting.")
        self.last_no_response_cleanup_time = datetime.now(timezone.utc) # Initialize last cleanup time
        
        while not self.stop_event.is_set(): # Loop until the stop event is set
            try:
                # Get packet data from the input queue with a timeout.
                # The timeout (e.g., 0.5 seconds) allows the loop to periodically check the stop_event
                # and perform other tasks (like cleanup) even if the queue is empty.
                packet_data = self.input_queue.get(timeout=0.5) 
                if packet_data:
                    self.process_packet(packet_data) # Process the received packet
                    self.input_queue.task_done() # Signal that the item from the queue has been processed
            except queue.Empty:
                # This exception occurs if input_queue.get() times out.
                # It's an expected condition and a good opportunity to perform periodic tasks.
                now = datetime.now(timezone.utc)
                if (now - self.last_no_response_cleanup_time).total_seconds() > 60: # Cleanup interval (e.g., 60s)
                    self.periodic_cleanup(now)
            except Exception as e:
                # Catch any other unexpected errors during the loop.
                print(f"Error in DetectionEngine loop: {e}") 
                # Consider more specific error handling or logging mechanisms for production.
                time.sleep(0.1) # Brief pause to avoid busy-looping on continuous errors.

        print(f"{self.getName()} stopping.")
        # Perform final cleanup before the thread exits.
        final_cleanup_time = datetime.now(timezone.utc)
        print(f"{self.getName()}: Performing final cleanup...")
        self.periodic_cleanup(final_cleanup_time)
        print(f"{self.getName()} finished cleanup and fully stopped.")


    def stop(self):
        """Signals the thread to stop its execution."""
        # This method is called from the main application thread (e.g., via atexit handler)
        # to request the DetectionEngine thread to terminate gracefully.
        print(f"Signalling {self.getName()} to stop.")
        self.stop_event.set() # Set the event. The run() loop will detect this and exit.

if __name__ == '__main__':
    # This block provides a test harness for the DetectionEngine.
    # It allows testing the engine's logic independently of the main Flask application and live packet capture.
    # It simulates packet data and verifies that alerts are generated as expected.
    print("Starting detection engine test...")
    test_q = queue.Queue()
    stop_ev = threading.Event()
    test_alerts_list = []

    def mock_logger(scan_type, timestamp, source_ip, destination_ip, destination_port, protocol, details):
        alert_msg = f"ALERT [{timestamp.isoformat()}]: {scan_type} from {source_ip} to {destination_ip}:{destination_port} ({protocol}). Details: {details}"
        print(alert_msg)
        test_alerts_list.append(alert_msg)

    engine = DetectionEngine(test_q, mock_logger, stop_ev)
    engine.start()

    base_time = datetime.now(timezone.utc)

    # --- Test Data Setup ---
    packets = []

    # 1. SYN Scan (High Rate to Port)
    syn_scan_source = '10.0.0.1'
    syn_scan_dest_ip = '192.168.1.100'
    syn_scan_dest_port = 80
    for i in range(engine.SYN_SCAN_THRESHOLD_COUNT + 5): # Exceed threshold
        packets.append({
            'timestamp': (base_time + timedelta(milliseconds=i * 100)).isoformat() + 'Z',
            'source_ip': syn_scan_source, 'destination_ip': syn_scan_dest_ip, 
            'destination_port': syn_scan_dest_port, 'protocol': 'TCP', 'flags': {'SYN': True}
        })

    # 2. SYN Scan (Multiple Ports on Dest)
    syn_multi_port_source = '10.0.0.2'
    syn_multi_port_dest_ip = '192.168.1.101'
    for i in range(engine.SYN_SCAN_TARGET_PORT_THRESHOLD + 3): # Exceed threshold
        packets.append({
            'timestamp': (base_time + timedelta(milliseconds=i * 150)).isoformat() + 'Z',
            'source_ip': syn_multi_port_source, 'destination_ip': syn_multi_port_dest_ip,
            'destination_port': 8000 + i, 'protocol': 'TCP', 'flags': {'SYN': True}
        })

    # 3. Horizontal Scan
    horizontal_scan_source = '10.0.0.3'
    for i in range(engine.HORIZONTAL_SCAN_PORT_THRESHOLD + 5): # Exceed threshold
        packets.append({
            'timestamp': (base_time + timedelta(milliseconds=i * 50)).isoformat() + 'Z',
            'source_ip': horizontal_scan_source, 'destination_ip': f'172.16.0.{i+1}',
            'destination_port': 1024 + i, 'protocol': 'TCP', 'flags': {'SYN': True}
        })
    
    # 4. No Response Scan
    no_response_source = '10.0.0.4'
    no_response_target_prefix = '192.168.2.'
    # Send probes
    for i in range(engine.NO_RESPONSE_SCAN_THRESHOLD_COUNT + 5): # Exceed threshold
        packets.append({
            'timestamp': (base_time + timedelta(milliseconds=i * 30)).isoformat() + 'Z',
            'source_ip': no_response_source, 'destination_ip': f'{no_response_target_prefix}{i+1}',
            'destination_port': 2000 + i, 'protocol': 'TCP', 'flags': {'SYN': True}
        })
    # Add one response for a different scanner to test response logic (won't affect no_response_source's scan)
    packets.append({
        'timestamp': (base_time + timedelta(milliseconds=100)).isoformat() + 'Z',
        'source_ip': '192.168.3.1', 'source_port': 80, # This is the target responding
        'destination_ip': '10.0.0.5', 'destination_port': 54321, # This is the scanner
        'protocol': 'TCP', 'flags': {'SYN': True, 'ACK': True}
    })


    # --- Send Packets ---
    for pkt in packets:
        test_q.put(pkt)
        time.sleep(0.005) # Simulate small delay

    print(f"\n--- All test packets ({len(packets)}) sent to queue. ---")
    
    # Wait for processing, including time for No Response Scan timeout
    # Max time window among rules + NO_RESPONSE_PROBE_TIMEOUT_SECONDS + buffer
    max_window = max(engine.SYN_SCAN_TIME_WINDOW_SECONDS, engine.HORIZONTAL_SCAN_TIME_WINDOW_SECONDS, engine.NO_RESPONSE_PROBE_TIMEOUT_SECONDS)
    wait_time = max_window + engine.NO_RESPONSE_PROBE_TIMEOUT_SECONDS + 2 
    print(f"Waiting for {wait_time} seconds for engine to process and trigger alerts (especially No Response Scan)...")
    
    # Check for alerts periodically while waiting
    for _ in range(int(wait_time / 0.5)):
        if stop_ev.is_set():
            break
        # Simulate some activity or just wait
        # The No Response scan relies on process_packet being called for the source IP,
        # or periodic cleanup. Let's send a dummy packet for the no_response_source to trigger its check.
        dummy_packet_time = base_time + timedelta(seconds=engine.NO_RESPONSE_PROBE_TIMEOUT_SECONDS + 1)
        test_q.put({
            'timestamp': dummy_packet_time.isoformat() + 'Z',
            'source_ip': no_response_source, 'destination_ip': '1.2.3.4', # Dummy target
            'destination_port': 1234, 'protocol': 'TCP', 'flags': {'SYN': True} # Another probe
        })
        time.sleep(0.5)


    print("\n--- Stopping engine... ---")
    stop_ev.set()
    engine.join(timeout=10) # Increased join timeout for CI/CD environments

    if engine.is_alive():
        print("Engine thread did not join cleanly!")
    
    print(f"\n--- Detection engine test finished. Total alerts generated: {len(test_alerts_list)} ---")
    # Basic validation of alerts
    assert any("SYN Scan (High Rate to Port)" in alert for alert in test_alerts_list), "Missing SYN Scan (High Rate) alert"
    assert any("SYN Scan (Multiple Ports on Dest)" in alert for alert in test_alerts_list), "Missing SYN Scan (Multi-Port) alert"
    assert any("Horizontal Scan" in alert for alert in test_alerts_list), "Missing Horizontal Scan alert"
    assert any("No Response Scan" in alert for alert in test_alerts_list), "Missing No Response Scan alert"
    print("Basic alert validation passed.")

