import threading
import time
import queue
# import pfring # Hypothetical
import subprocess # For tcpdump fallback
import re # For parsing tcpdump output
from datetime import datetime, timezone# For timestamp consistency

# Basic data class for holding extracted packet information
class PacketData:
    """
    Represents a single captured network packet's relevant information.
    Updated to include all fields needed for the modified database schema.
    """
    def __init__(self, timestamp, protocol, source_ip, destination_ip, 
                 destination_port, flags=None, details="", severity="MEDIUM", source_port=None):
        """
        Args:
            timestamp (datetime): Packet capture time
            protocol (str): TCP/UDP/ICMP
            source_ip (str): Source IP address
            destination_ip (str): Destination IP address
            destination_port (int/str): Destination port
            flags (dict): TCP flags like {'SYN': True, 'ACK': False}
            details (str): Additional packet info
            severity (str): LOW/MEDIUM/HIGH/CRITICAL
            source_port (int/str): Source port (optional)
        """
        self.timestamp = timestamp
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.flags = flags if flags is not None else {}
        self.details = details
        self.severity = severity  # New field added

    def __repr__(self):
        return (f"PacketData(timestamp={self.timestamp}, protocol={self.protocol}, "
                f"source={self.source_ip}:{self.source_port}, "
                f"destination={self.destination_ip}:{self.destination_port}, "
                f"flags={self.flags}, severity={self.severity}, "
                f"details='{self.details[:50]}...'")

    def to_dict(self):
        """Converts to dictionary with all fields needed for database logging"""
        return {
            "timestamp": self.timestamp.replace(tzinfo=timezone.utc).isoformat() 
                         if isinstance(self.timestamp, datetime) 
                         else datetime.now(timezone.utc).isoformat(),
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "flags": self.flags,
            "severity": self.severity,  # Included in dict
            "details": self.details
        }

class PacketCaptureThread(threading.Thread):
    """
    A thread responsible for capturing network packets from a specified interface.
    It can use PF_RING if available (currently placeholder) or falls back to tcpdump.
    Captured and parsed packet data is put onto a shared queue for processing.
    """
    def __init__(self, data_queue, interface="wlp2s0", stop_event=None):
        super().__init__()
        self.setName(f"PacketCaptureThread-{interface}") # Set thread name for easier debugging
        self.data_queue = data_queue # queue.Queue object to pass PacketData (as dicts) to the engine
        self.interface = interface   # Network interface to capture from (e.g., 'wlp2s0', 'eth0')
        self.stop_event = stop_event or threading.Event() # threading.Event to signal thread termination
        self.use_pfring = False      # Flag to indicate if PF_RING is active (currently always False)
        self.pf_socket = None        # Placeholder for PF_RING socket object
        
        if not self.use_pfring:
            # This message clarifies that tcpdump is the active capture method.
            print(f"{self.getName()}: PF_RING not available/initialized. Using tcpdump for packet capture on {self.interface}.")


    def parse_tcpdump_line(self, line):
        """
        Parses a single line of tcpdump output to extract packet information.
        Enhanced to include all fields needed for the updated database schema.

        Args:
            line (str): A line of tcpdump output

        Returns:
            PacketData or None: Parsed packet data with all required fields
        """
        try:
            if not line.strip():
                return None

            # Debug: Print raw tcpdump line
            if "TCP" in line or "UDP" in line or "ICMP" in line:
                print(f"[DEBUG] Parsing tcpdump line: {line.strip()}")

            parts = line.split()
            if len(parts) < 6:
                return None

            # Find IP protocol marker
            ip_index = -1
            for i, part in enumerate(parts):
                if part in {"IP", "IP6"}:
                    ip_index = i
                    break
            
            if ip_index == -1:
                return None

            # Timestamp parsing with microseconds fallback
            timestamp_str = parts[0] + " " + parts[1]
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    print(f"[DEBUG] Timestamp parse failed: {timestamp_str}")
                    timestamp = datetime.now()

            # Initialize with default severity
            protocol = None
            severity = "MEDIUM"  # Default value
            source_ip, source_port = None, None
            dest_ip, dest_port = None, None
            flags = {}
            details = line.strip()

            # --- Correction ici : Séparation robuste IP/port ---
            def split_ip_port(ip_port_str):
                # Gère les cas du type "192.168.0.108.57738"
                if ip_port_str.count('.') >= 4:
                    ip, port = ip_port_str.rsplit('.', 1)
                    if port.isdigit():
                        return ip, int(port)
                    else:
                        return ip_port_str, None
                return ip_port_str, None

            # Extract source and destination (they should be right after IP marker)
            if ip_index + 1 < len(parts) and ip_index + 3 < len(parts):
                src_full = parts[ip_index + 1]
                dst_full = parts[ip_index + 3].rstrip(':')

                source_ip, source_port = split_ip_port(src_full)
                dest_ip, dest_port = split_ip_port(dst_full)

            # Protocol and flags detection
            if "TCP" in line or any(f in line for f in ["Flags", "S ", "F ", "R ", "P ", "U ", "ack "]):
                protocol = "TCP"
                flag_match = re.search(r"Flags \[([SFPUR.]+)\]", line)
                
                if flag_match:
                    flag_chars = flag_match.group(1)
                    flags = {
                        'SYN': 'S' in flag_chars,
                        'FIN': 'F' in flag_chars,
                        'RST': 'R' in flag_chars,
                        'PSH': 'P' in flag_chars,
                        'URG': 'U' in flag_chars,
                        'ACK': '.' in flag_chars
                    }
                    # Adjust severity based on flags
                    if flags.get('RST'):
                        severity = "HIGH"
                    elif flags.get('SYN') and not flags.get('ACK'):
                        severity = "MEDIUM"
                        print(f"[DEBUG] Detected SYN packet: {source_ip}:{source_port} -> {dest_ip}:{dest_port}")
                else:
                    # Fallback flag detection
                    flags = {
                        'SYN': ' S ' in line or line.endswith(' S'),
                        'FIN': ' F ' in line or line.endswith(' F'),
                        'RST': ' R ' in line or line.endswith(' R'),
                        'PSH': ' P ' in line or line.endswith(' P'),
                        'URG': ' U ' in line or line.endswith(' U'),
                        'ACK': 'ack' in line.lower() or ' . ' in line
                    }

            elif "UDP" in line:
                protocol = "UDP"
                # Extract UDP length for flood detection
                length_match = re.search(r"length (\d+)", line)
                if length_match and int(length_match.group(1)) > 1000:
                    severity = "HIGH"

            elif "ICMP" in line:
                protocol = "ICMP"
                icmp_match = re.search(r"ICMP (.*?),", line)
                if icmp_match:
                    details = f"ICMP {icmp_match.group(1)}"
                    if "unreachable" in icmp_match.group(1).lower():
                        severity = "MEDIUM"

            # Create PacketData object with all fields
            if protocol and source_ip and dest_ip:
                packet_data = PacketData(
                    timestamp=timestamp,
                    protocol=protocol,
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_ip=dest_ip,
                    destination_port=dest_port or 0,
                    flags=flags,
                    severity=severity,
                    details=details
                )
                print(f"[DEBUG] Successfully parsed packet: {packet_data}")
                return packet_data

            return None

        except Exception as e:
            print(f"[ERROR] Parser error in line '{line[:100]}...': {str(e)}")
            return None


    def run_pfring_capture(self):
        # This method is a placeholder for PF_RING based capture logic.
        print(f"{self.getName()}: PF_RING direct capture method called but not implemented/available.")
        self.use_pfring = False
        if self.pf_socket:
            print(f"{self.getName()}: Hypothetical PF_RING socket closed.")


    def run_tcpdump_capture(self):
        """
        Captures packets using tcpdump run as a subprocess.
        Parses each line of tcpdump output and puts structured data onto the data_queue.
        Handles process startup, termination, and error conditions.
        """
        print(f"{self.getName()}: Starting tcpdump capture on interface '{self.interface}'...")
        
        # Updated tcpdump command for better packet capture on wlp2s0
        # Removed network filter to capture all traffic on the interface
        # Added -s 0 to capture full packets
        # Simplified filter to catch more packets
        cmd = [
            "sudo", "tcpdump", 
            "-i", self.interface,    # Interface
            "-l",                    # Line buffered
            "-n",                    # No name resolution
            "-tttt",                 # Absolute timestamp
            "-s", "0",              # Capture full packets
            "tcp or udp or icmp"     # Simplified filter - no network restriction
        ]
        
        print(f"[DEBUG] Running command: {' '.join(cmd)}")
        
        process = None
        try:
            # Start the tcpdump process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            print(f"{self.getName()}: Tcpdump process started (PID: {process.pid}) on interface '{self.interface}'.")

            # Read tcpdump output line by line
            for line in iter(process.stdout.readline, ''):
                if self.stop_event.is_set():
                    print(f"{self.getName()}: Stop event received, breaking from tcpdump loop.")
                    break
                
                if line.strip():  # Only process non-empty lines
                    packet_info = self.parse_tcpdump_line(line.strip())
                    if packet_info:
                        # Put packet data onto queue
                        packet_dict = packet_info.to_dict()
                        self.data_queue.put(packet_dict)
                        print(f"[DEBUG] Packet queued: {packet_dict['source_ip']}:{packet_dict['source_port']} -> {packet_dict['destination_ip']}:{packet_dict['destination_port']} [{packet_dict['protocol']}]")
            
            # Check if tcpdump exited prematurely
            if process.poll() is not None and not self.stop_event.is_set():
                print(f"{self.getName()}: Tcpdump process exited prematurely with code {process.returncode}.")
                stderr_output = process.stderr.read()
                if stderr_output:
                    print(f"{self.getName()} tcpdump stderr:\n{stderr_output}")

        except FileNotFoundError:
            print(f"{self.getName()}: Error - tcpdump command not found. Please ensure it's installed and in PATH.")
            self.data_queue.put({"error": "tcpdump_not_found", "interface": self.interface})
        except PermissionError:
            print(f"{self.getName()}: Error - Permission denied to run tcpdump. Ensure sudo privileges.")
            print(f"Try running: sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)")
            self.data_queue.put({"error": "tcpdump_permission_denied", "interface": self.interface})
        except Exception as e:
            print(f"{self.getName()}: An error occurred during tcpdump capture: {e}")
            self.data_queue.put({"error": str(e), "interface": self.interface})
        finally:
            # Cleanup tcpdump process
            if process:
                if process.poll() is None:
                    print(f"{self.getName()}: Terminating tcpdump process (PID: {process.pid})...")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                        print(f"{self.getName()}: Tcpdump process terminated.")
                    except subprocess.TimeoutExpired:
                        print(f"{self.getName()}: Tcpdump did not terminate gracefully, sending SIGKILL.")
                        process.kill()
                        process.wait()
                        print(f"{self.getName()}: Tcpdump process killed.")
                else:
                    print(f"{self.getName()}: Tcpdump process (PID: {process.pid}) already exited with code {process.returncode}.")
                
                # Close pipes
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    remaining_stderr = process.stderr.read()
                    if remaining_stderr:
                        print(f"{self.getName()} remaining tcpdump stderr:\n{remaining_stderr}")
                    process.stderr.close()
            print(f"{self.getName()}: Tcpdump capture process for interface '{self.interface}' stopped.")


    def run(self):
        """Main execution method for the thread."""
        print(f"{self.getName()}: Starting packet capture on interface '{self.interface}'")
        self.run_tcpdump_capture()
        print(f"{self.getName()}: Finished run method. Thread will exit.")


    def stop(self):
        """Signals the thread to stop its execution."""
        print(f"{self.getName()}: Stopping packet capture thread for interface '{self.interface}'...")
        self.stop_event.set()

if __name__ == '__main__':
    # Test the PacketCaptureThread
    print("Starting packet capture test on wlp2s0...")
    print("Make sure to run this script with sudo: sudo python ids_capture.py")
    test_q = queue.Queue()
    capture_stop_event = threading.Event()
    
    # Test with wlp2s0 interface
    interface_to_test = "wlp2s0" 
    print(f"Attempting to capture on interface: {interface_to_test}")
    print("You can test by running: sudo nmap -sS -p 80,443,22 192.168.0.108")

    capture_thread = PacketCaptureThread(test_q, interface=interface_to_test, stop_event=capture_stop_event)
    capture_thread.start()

    try:
        # Let it run for a bit to capture some packets
        print("Capture thread started. Listening for packets for up to 30 seconds...")
        print("Run 'sudo nmap -sS -p 80,443,22 192.168.0.108' in another terminal to generate traffic.")
        
        packet_count = 0
        for i in range(30):  # Check queue every second for 30 seconds
            if not capture_thread.is_alive() and test_q.empty():
                print("Capture thread died unexpectedly and queue is empty.")
                break
            try:
                packet_dict = test_q.get(timeout=1)  # Wait 1 second for a packet
                packet_count += 1
                print(f"[{datetime.now()}] Packet #{packet_count}: {packet_dict['source_ip']}:{packet_dict['source_port']} -> {packet_dict['destination_ip']}:{packet_dict['destination_port']} [{packet_dict['protocol']}] Flags: {packet_dict['flags']}")
            except queue.Empty:
                if i % 10 == 0:  # Print a message every 10 seconds if queue is empty
                    print(f"Queue empty at {i+1}s, waiting for packets...")
            if capture_stop_event.is_set():
                print("Stop event was set externally during test loop.")
                break
        
        print(f"\nTotal packets captured: {packet_count}")
        
        # Drain any remaining packets
        if not test_q.empty():
            print("Draining any remaining packets from queue...")
            remaining = 0
            while not test_q.empty():
                try:
                    packet_dict = test_q.get_nowait()
                    remaining += 1
                    print(f"Drained packet #{packet_count + remaining}: {packet_dict['source_ip']} -> {packet_dict['destination_ip']}")
                except queue.Empty:
                    break
            print(f"Drained {remaining} additional packets.")
        
    except KeyboardInterrupt:
        print("\nUser interrupted test with Ctrl+C.")
    finally:
        print("\nStopping capture thread from main test...")
        if not capture_stop_event.is_set():
            capture_stop_event.set()
        
        capture_thread.join(timeout=10)
        if capture_thread.is_alive():
            print("Capture thread did not join cleanly.")
        else:
            print("Capture thread joined successfully.")
        print("Packet capture test finished.")