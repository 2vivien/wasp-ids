import threading
import time
import queue
# import pfring # Hypothetical
import subprocess # For tcpdump fallback
import re # For parsing tcpdump output
from datetime import datetime # For timestamp consistency

# Basic data class for holding extracted packet information
class PacketData:
    """
    Represents a single captured network packet's relevant information.
    Used to standardize data format before passing it to the detection engine.
    """
    def __init__(self, timestamp, protocol, source_ip, source_port, 
                 destination_ip, destination_port, flags=None, details=""):
        self.timestamp = timestamp          # datetime object of packet capture
        self.protocol = protocol            # Protocol (TCP, UDP, ICMP)
        self.source_ip = source_ip          # Source IP address
        self.source_port = source_port      # Source port (if applicable)
        self.destination_ip = destination_ip # Destination IP address
        self.destination_port = destination_port # Destination port (if applicable)
        self.flags = flags if flags is not None else {} # TCP flags (e.g., {'SYN': True, 'ACK': True})
        self.details = details              # Raw line or specific ICMP type for context

    def __repr__(self):
        return (f"PacketData(timestamp={self.timestamp}, protocol={self.protocol}, "
                f"source_ip={self.source_ip}:{self.source_port}, "
                f"destination_ip={self.destination_ip}:{self.destination_port}, "
                f"flags={self.flags}, details='{self.details}')")

    def to_dict(self):
        """Converts PacketData object to a dictionary for queuing and processing."""
        return {
            "timestamp": self.timestamp.isoformat() + 'Z' if isinstance(self.timestamp, datetime) else self.timestamp,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "flags": self.flags,
            "details": self.details
        }

class PacketCaptureThread(threading.Thread):
    """
    A thread responsible for capturing network packets from a specified interface.
    It can use PF_RING if available (currently placeholder) or falls back to tcpdump.
    Captured and parsed packet data is put onto a shared queue for processing.
    """
    def __init__(self, data_queue, interface="eth0", stop_event=None):
        super().__init__()
        self.setName(f"PacketCaptureThread-{interface}") # Set thread name for easier debugging
        self.data_queue = data_queue # queue.Queue object to pass PacketData (as dicts) to the engine
        self.interface = interface   # Network interface to capture from (e.g., 'eth0', 'lo')
        self.stop_event = stop_event or threading.Event() # threading.Event to signal thread termination
        self.use_pfring = False      # Flag to indicate if PF_RING is active (currently always False)
        self.pf_socket = None        # Placeholder for PF_RING socket object

        # --- PF_RING Initialization Placeholder ---
        # The following block is conceptual and non-operational.
        # PF_RING Python bindings were not available/integrated in this project iteration.
        # If PF_RING were to be used, proper library import and initialization would occur here.
        # This section is clearly marked as a non-operational placeholder.
        # try:
        #     import pfring # Example: actual library name might differ
        #     # self.pf_socket = pfring.Socket()
        #     # self.pf_socket.open_device(self.interface)
        #     # ... more pfring setup ...
        #     self.use_pfring = True
        #     print("Hypothetically initialized PF_RING.")
        # except ImportError:
        #     print("PF_RING Python library not found. This is expected.")
        # except Exception as e:
        #     print(f"Hypothetical PF_RING init error: {e}")
        #     self.use_pfring = False
        # --- End of PF_RING Placeholder ---
        
        if not self.use_pfring:
            # This message clarifies that tcpdump is the active capture method.
            print(f"{self.getName()}: PF_RING not available/initialized. Defaulting to tcpdump for packet capture.")


    def parse_tcpdump_line(self, line):
        """
        Parses a single line of tcpdump output to extract packet information.

        Args:
            line (str): A line of output from the tcpdump process.

        Returns:
            PacketData or None: A PacketData object if parsing is successful, otherwise None.

        Expected tcpdump line formats (examples):
        - TCP:  YYYY-MM-DD HH:MM:SS.ffffff IP <src_ip>.<src_port> > <dst_ip>.<dst_port>: Flags [<flag_chars>], ...
        - UDP:  YYYY-MM-DD HH:MM:SS.ffffff IP <src_ip>.<src_port> > <dst_ip>.<dst_port>: UDP, length <len>
        - ICMP: YYYY-MM-DD HH:MM:SS.ffffff IP <src_ip> > <dst_ip>: ICMP <type>, ...
        The parser focuses on IP packets and extracts common fields like timestamp, IPs, ports, protocol, and TCP flags.
        """
        try:
            parts = line.split() # Split line by whitespace; robust for typical tcpdump output.
            # Basic validation: must have enough parts and be an IP packet (parts[2] is typically 'IP').
            if len(parts) < 5 or parts[2] != "IP": 
                return None

            # Timestamp parsing (expected format: YYYY-MM-DD HH:MM:SS.ffffff)
            timestamp_str = parts[0] + " " + parts[1]
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError: # Fallback if microseconds are missing or format varies slightly
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            protocol = None
            source_ip, source_port_str = None, None # Keep port as string initially for non-numeric cases (e.g. ICMP 'echo request')
            dest_ip, dest_port_str = None, None
            flags = {} # Dictionary to store TCP flags if present
            details_str = line # Default details to the full line; refined for ICMP.

            # Source IP and Port (parts[3]): e.g., "192.168.1.10.54321" or "192.168.1.10.http"
            # For ICMP, this might just be an IP or hostname if -n is not used strictly.
            src_full = parts[3]
            # Destination IP and Port (parts[5], removing trailing ':'): e.g., "192.168.1.20.80:"
            dst_full = parts[5].rstrip(':')

            # Extract IP and Port from "IP.Port" strings using rpartition.
            # rpartition splits the string at the last occurrence of the separator ('.').
            # This correctly handles FQDNs like "host.domain.com.port" by separating "host.domain.com" from "port".
            src_ip_parts = src_full.rpartition('.')
            source_ip = src_ip_parts[0]
            source_port_str = src_ip_parts[2]

            dst_ip_parts = dst_full.rpartition('.')
            dest_ip = dst_ip_parts[0]
            dest_port_str = dst_ip_parts[2]

            # Convert port strings to int if they are digits. Otherwise, keep as string 
            # (e.g., for ICMP types like 'echo request', or named services like 'http' if -n not fully effective).
            source_port = int(source_port_str) if source_port_str.isdigit() else source_port_str
            dest_port = int(dest_port_str) if dest_port_str.isdigit() else dest_port_str
            
            # Protocol and TCP Flags determination.
            # This relies on keyword checking in the tcpdump output line, which is standard.
            if "TCP" in line: # Check if "TCP" substring is present in the line.
                protocol = "TCP"
                # Regex for TCP flags: e.g., "Flags [S.]", "Flags [P.]", "Flags [FSRAPU]".
                # The regex captures characters within the square brackets following "Flags ".
                flag_match = re.search(r"Flags \[(.*?)\]", line)
                if flag_match:
                    flag_chars = flag_match.group(1) # The characters representing flags (e.g., "S", "S.", "PA")
                    if 'S' in flag_chars: flags['SYN'] = True
                    if '.' in flag_chars: flags['ACK'] = True # '.' often denotes ACK in tcpdump when other flags (like SYN, PSH) are also set.
                    if 'F' in flag_chars: flags['FIN'] = True
                    if 'R' in flag_chars: flags['RST'] = True
                    if 'P' in flag_chars: flags['PSH'] = True
                    if 'U' in flag_chars: flags['URG'] = True
                # Fallback: Check for standalone "ack" if not in Flags field (can happen in some tcpdump outputs for pure ACKs).
                if not flags.get('ACK') and " ack " in line: # Check for " ack " with spaces to avoid matching 'tcpacknowledgement'.
                    flags['ACK'] = True

            elif "UDP" in line: # Check for "UDP" substring.
                protocol = "UDP"
            elif "ICMP" in line: # Check for "ICMP" substring.
                protocol = "ICMP"
                # For ICMP, source_port and dest_port might be non-numeric (e.g., 'echo request').
                # Try to extract more specific ICMP type/code from the line for better detail.
                icmp_type_match = re.search(r"ICMP (echo request|echo reply|destination unreachable|time exceeded|redirect)", line, re.IGNORECASE)
                if icmp_type_match:
                    details_str = f"ICMP {icmp_type_match.group(1)}" # Use matched ICMP type as detail.
                else:
                    details_str = "ICMP packet" # Generic ICMP detail if specific type not matched.

            if protocol and source_ip and dest_ip: # Ensure essential fields were successfully parsed.
                return PacketData(
                    timestamp=timestamp, protocol=protocol,
                    source_ip=source_ip, source_port=source_port,
                    destination_ip=dest_ip, destination_port=dest_port,
                    flags=flags, details=details_str
                )
            return None # Return None if parsing fails to meet criteria (e.g., not an IP packet, or essential fields missing).
        except Exception as e:
            # print(f"Error parsing line: '{line.strip()}' -> {e}") # Uncomment for debugging parsing errors.
            return None

    def run_pfring_capture(self):
        # This method is a placeholder for PF_RING based capture logic.
        # It is currently NOT USED as PF_RING is not integrated.
        # PF_RING would offer higher performance packet capture by bypassing the kernel's networking stack.
        print(f"{self.getName()}: PF_RING direct capture method called but not implemented/available.")
        # If this were implemented, it would involve:
        # - A loop similar to run_tcpdump_capture but using pf_socket.recv() or similar.
        # - Parsing raw packet bytes (e.g., Ethernet frames, IP headers, TCP/UDP segments).
        #   Libraries like 'dpkt' or 'scapy' could be used for this, or manual parsing for extreme performance.
        # - Populating PacketData from these headers.
        # - Handling the stop_event to terminate the loop gracefully.
        self.use_pfring = False # Ensure this remains false as PF_RING is not active.
        if self.pf_socket: # Hypothetical cleanup for a PF_RING socket.
            # self.pf_socket.shutdown() # Example: Actual PF_RING API call might differ.
            # self.pf_socket.close()
            print(f"{self.getName()}: Hypothetical PF_RING socket closed.")


    def run_tcpdump_capture(self):
        """
        Captures packets using tcpdump run as a subprocess.
        Parses each line of tcpdump output and puts structured data onto the data_queue.
        Handles process startup, termination, and error conditions.
        """
        print(f"{self.getName()}: Starting tcpdump capture on interface '{self.interface}'...")
        
        # tcpdump command construction:
        # - sudo: Required for capturing on most interfaces, unless specific capabilities (e.g., CAP_NET_RAW, CAP_NET_ADMIN) 
        #         are set for the tcpdump executable or the user running the script. This is a security consideration.
        # - -i {self.interface}: Specify the network interface to capture from (e.g., 'eth0', 'lo').
        # - -l: Line-buffer output. This is crucial for reading output line by line from the subprocess in real-time.
        # - -n: No name resolution (show IPs and ports as numbers, avoids potentially slow DNS lookups).
        # - -tttt: Absolute timestamp format (YYYY-MM-DD HH:MM:SS.ffffff), good for precise timing of packets.
        # - 'tcp or udp or icmp': Berkeley Packet Filter (BPF) expression to capture only TCP, UDP, or ICMP packets, 
        #                         which are the primary protocols relevant for common scan detection.
        cmd = ["sudo", "tcpdump", "-i", self.interface, "-l", "-n", "-tttt", "tcp or udp or icmp"]
        
        process = None # To hold the subprocess.Popen object for tcpdump.
        try:
            # Start the tcpdump process.
            # stdout and stderr are piped to be read by this script.
            # text=True decodes output as text (UTF-8 by default). bufsize=1 enables line buffering for stdout.
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            print(f"{self.getName()}: Tcpdump process started (PID: {process.pid}) on interface '{self.interface}'.")

            # Read tcpdump output line by line as it becomes available.
            # iter(process.stdout.readline, '') creates an iterator that calls readline until it returns an empty string 
            # (which signifies that the tcpdump process has closed its stdout, e.g., upon termination).
            for line in iter(process.stdout.readline, ''):
                if self.stop_event.is_set(): # Check if termination is requested by the main application.
                    print(f"{self.getName()}: Stop event received, breaking from tcpdump loop.")
                    break # Exit the loop to allow the thread to terminate gracefully.
                
                packet_info = self.parse_tcpdump_line(line.strip()) # Parse the captured line.
                if packet_info:
                    # If parsing is successful, put the packet data (as a dictionary) onto the shared data_queue.
                    # The DetectionEngine thread will pick it up from this queue for analysis.
                    self.data_queue.put(packet_info.to_dict()) 
            
            # After the loop, check if the tcpdump process exited prematurely (i.e., not due to stop_event).
            # process.poll() returns the exit code if the process has terminated, or None otherwise.
            if process.poll() is not None and not self.stop_event.is_set():
                print(f"{self.getName()}: Tcpdump process exited prematurely with code {process.returncode}.")
                stderr_output = process.stderr.read() # Read any error messages from tcpdump's stderr.
                if stderr_output:
                    print(f"{self.getName()} tcpdump stderr:\n{stderr_output}")

        except FileNotFoundError:
            # This exception occurs if 'tcpdump' (or 'sudo') command is not found in the system's PATH.
            print(f"{self.getName()}: Error - tcpdump command not found. Please ensure it's installed and in PATH.")
            # Put an error message on the queue so the main app/engine is aware of this critical failure if needed.
            self.data_queue.put({"error": "tcpdump_not_found", "interface": self.interface})
        except PermissionError:
            # This exception typically occurs if the script does not have sufficient privileges 
            # to run tcpdump (e.g., trying to capture on 'eth0' without sudo).
            print(f"{self.getName()}: Error - Permission denied to run tcpdump. Ensure sudo privileges or proper capabilities for tcpdump.")
            self.data_queue.put({"error": "tcpdump_permission_denied", "interface": self.interface})
        except Exception as e:
            # Catch any other unexpected errors during tcpdump execution or setup.
            print(f"{self.getName()}: An error occurred during tcpdump capture: {e}")
            self.data_queue.put({"error": str(e), "interface": self.interface})
        finally:
            # Cleanup: Ensure the tcpdump process is terminated if it's still running when this block is reached.
            if process:
                if process.poll() is None: # Check if process is still running.
                    print(f"{self.getName()}: Terminating tcpdump process (PID: {process.pid})...")
                    process.terminate() # Send SIGTERM, allowing tcpdump to shut down gracefully (e.g., flush buffers).
                    try:
                        process.wait(timeout=5) # Wait up to 5 seconds for graceful termination.
                        print(f"{self.getName()}: Tcpdump process terminated.")
                    except subprocess.TimeoutExpired:
                        # If tcpdump doesn't terminate gracefully within the timeout, force kill it with SIGKILL.
                        print(f"{self.getName()}: Tcpdump did not terminate gracefully, sending SIGKILL.")
                        process.kill() 
                        process.wait() # Ensure the process is reaped after SIGKILL.
                        print(f"{self.getName()}: Tcpdump process killed.")
                else: # Process already exited.
                    print(f"{self.getName()}: Tcpdump process (PID: {process.pid}) already exited with code {process.returncode}.")
                
                # Close stdout/stderr pipes associated with the process to free resources.
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    remaining_stderr = process.stderr.read() # Read any final error messages.
                    if remaining_stderr:
                        print(f"{self.getName()} remaining tcpdump stderr:\n{remaining_stderr}")
                    process.stderr.close()
            print(f"{self.getName()}: Tcpdump capture process for interface '{self.interface}' stopped.")


    def run(self):
        """Main execution method for the thread."""
        # This thread's primary role is to start and manage the packet capture mechanism.
        # Currently, PF_RING is not used (self.use_pfring is False), so it directly calls the tcpdump capture method.
        # if self.use_pfring and self.pf_socket: # This condition is currently always false.
        #     self.run_pfring_capture() # Hypothetical call to PF_RING capture logic.
        # else:
        #     if not self.use_pfring: # This will always be true in the current implementation.
        #         print(f"{self.getName()}: PF_RING not used/failed, proceeding with tcpdump.")
        #     self.run_tcpdump_capture() # Execute tcpdump based capture.
        
        print(f"{self.getName()}: Defaulting to tcpdump capture method as PF_RING is not active.")
        self.run_tcpdump_capture() # Start the tcpdump capture process.
        print(f"{self.getName()}: Finished run method. Thread will exit.")


    def stop(self):
        """Signals the thread to stop its execution."""
        # This method is called from the main application thread (e.g., via an atexit handler in app.py)
        # to request the capture thread to terminate its operations gracefully.
        print(f"{self.getName()}: Stopping packet capture thread for interface '{self.interface}'...")
        self.stop_event.set() # Set the threading.Event. Loops and processes within the run() method should check this event.

if __name__ == '__main__':
    # This block is for testing the PacketCaptureThread independently of the main Flask application.
    # It demonstrates how to instantiate and start the thread, simulate packet capture for a short duration, 
    # retrieve packets from the queue, and then stop the thread.
    # To run this test effectively, especially with a real interface like 'eth0',
    # you would typically need to execute this script with sudo: `sudo python ids_capture.py`.
    print("Starting packet capture test (run this script with sudo if using a real interface like 'eth0')...")
            if len(parts) < 5 or parts[2] != "IP":
                return None

            timestamp_str = parts[0] + " " + parts[1]
            # Attempt to parse the timestamp with microseconds
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                # Fallback if microseconds are missing or format varies slightly
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            protocol = None
            source_ip, source_port = None, None
            dest_ip, dest_port = None, None
            flags = {}
            details_str = line

            # Source and Destination parsing
            src_full = parts[3]
            dst_full = parts[5].rstrip(':') # Remove trailing colon if present

            src_parts = src_full.rpartition('.')
            source_ip = src_parts[0]
            if src_parts[2].isdigit():
                source_port = int(src_parts[2])
            else: # Could be a service name for ICMP or if port is not numeric
                source_port = src_parts[2] 

            dst_parts = dst_full.rpartition('.')
            dest_ip = dst_parts[0]
            if dst_parts[2].isdigit():
                dest_port = int(dst_parts[2])
            else:
                dest_port = dst_parts[2]

            # Protocol and Flags parsing
            if "TCP" in line:
                protocol = "TCP"
                flag_match = re.search(r"Flags \[(.*?)\]", line)
                if flag_match:
                    flag_str = flag_match.group(1)
                    if 'S' in flag_str: flags['SYN'] = True
                    if '.' in flag_str or 'ack' in line.lower(): flags['ACK'] = True # tcpdump shows '.' for ACK sometimes
                    if 'F' in flag_str: flags['FIN'] = True
                    if 'R' in flag_str: flags['RST'] = True
                    if 'P' in flag_str: flags['PSH'] = True
                    if 'U' in flag_str: flags['URG'] = True
            elif "UDP" in line:
                protocol = "UDP"
            elif "ICMP" in line:
                protocol = "ICMP"
                # For ICMP, source_port and dest_port might not be numbers (e.g., 'echo request')
                # We keep them as strings if they are not digits.
                # Extract ICMP type/code if possible
                icmp_type_match = re.search(r"ICMP (echo request|echo reply|destination unreachable|time exceeded|redirect)", line, re.IGNORECASE)
                if icmp_type_match:
                    details_str = f"ICMP {icmp_type_match.group(1)}"
                else:
                    details_str = "ICMP packet"


            if protocol and source_ip and dest_ip: # Basic validation
                return PacketData(
                    timestamp=timestamp, protocol=protocol,
                    source_ip=source_ip, source_port=source_port,
                    destination_ip=dest_ip, destination_port=dest_port,
                    flags=flags, details=details_str
                )
            return None
        except Exception as e:
            # print(f"Error parsing line: '{line.strip()}' -> {e}") # For debugging
            return None

    def run_pfring_capture(self):
        # This is where actual PF_RING packet processing would go.
        # Since we are defaulting to tcpdump, this method remains a placeholder.
        print("PF_RING direct capture not implemented/available in this environment.")
        print("This function would contain PF_RING specific packet capture and parsing logic.")
        # Simulate immediate stop if this were ever called without full implementation
        self.use_pfring = False 
        # if self.pf_socket:
        #    self.pf_socket.close()
        #    print("PF_RING socket closed (hypothetical).")


    def run_tcpdump_capture(self):
        print(f"Starting tcpdump capture on interface {self.interface}...")
        # The command uses 'sudo'. This implies the script needs to be run with root privileges,
        # or tcpdump needs to be granted specific capabilities (e.g., CAP_NET_RAW, CAP_NET_ADMIN).
        # This is an important security consideration for deployment.
        # Filter: 'tcp or udp or icmp' captures the most common protocols for scanning.
        # -tttt: absolute timestamp
        # -n: no name resolution (gives IPs)
        # -l: line-buffered output
        cmd = ["sudo", "tcpdump", "-i", self.interface, "-l", "-n", "-tttt", "tcp or udp or icmp"]
        
        process = None
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            
            print(f"Tcpdump process started with PID: {process.pid} on interface {self.interface}")

            for line in iter(process.stdout.readline, ''):
                if self.stop_event.is_set():
                    print("Stop event received, breaking from tcpdump loop.")
                    break
                
                # print(f"Raw line: {line.strip()}") # Debugging: print raw line
                packet_info = self.parse_tcpdump_line(line.strip())
                if packet_info:
                    # print(f"Parsed: {packet_info.to_dict()}") # Debugging: print parsed data
                    self.data_queue.put(packet_info.to_dict()) # Put dict representation on queue
            
            # Check if process exited prematurely
            if process.poll() is not None and not self.stop_event.is_set():
                print(f"Tcpdump process exited prematurely with code {process.returncode}.")
                stderr_output = process.stderr.read()
                if stderr_output:
                    print(f"Tcpdump stderr:\n{stderr_output}")


        except FileNotFoundError:
            print(f"Error: tcpdump command not found. Please ensure it's installed and in PATH.")
            # Consider putting an error object or special message on the queue
            self.data_queue.put({"error": "tcpdump_not_found", "interface": self.interface})
        except PermissionError:
            print(f"Error: Permission denied to run tcpdump. Ensure you have root/sudo privileges or proper capabilities.")
            self.data_queue.put({"error": "tcpdump_permission_denied", "interface": self.interface})
        except Exception as e:
            print(f"An error occurred during tcpdump capture: {e}")
            self.data_queue.put({"error": str(e), "interface": self.interface})
        finally:
            if process:
                if process.poll() is None: # If process is still running
                    print("Terminating tcpdump process...")
                    process.terminate() # Send SIGTERM
                    try:
                        process.wait(timeout=5) # Wait for graceful termination
                        print("Tcpdump process terminated.")
                    except subprocess.TimeoutExpired:
                        print("Tcpdump did not terminate gracefully after SIGTERM, sending SIGKILL.")
                        process.kill() # Send SIGKILL
                        process.wait() # Ensure it's reaped
                        print("Tcpdump process killed.")
                else:
                    print(f"Tcpdump process already exited with code {process.returncode}.")
                
                # Ensure stdout/stderr are closed
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    # Read and print any remaining stderr output
                    remaining_stderr = process.stderr.read()
                    if remaining_stderr:
                        print(f"Remaining tcpdump stderr:\n{remaining_stderr}")
                    process.stderr.close()
            print(f"Tcpdump capture process for interface {self.interface} stopped.")


    def run(self):
        # The problem description guides to default to tcpdump.
        # if self.use_pfring and self.pf_socket:
        #     self.run_pfring_capture()
        # else:
        #     if not self.use_pfring:
        #         print("PF_RING not used or failed initialization, proceeding with tcpdump.")
        #     self.run_tcpdump_capture()
        
        print("Defaulting to tcpdump capture method as per subtask instructions.")
        self.run_tcpdump_capture()
        print(f"PacketCaptureThread for interface {self.interface} finished run method.")


    def stop(self):
        print(f"Stopping packet capture thread for interface {self.interface}...")
        self.stop_event.set()

if __name__ == '__main__':
    print("Starting packet capture test (run this script with sudo if using a real interface like 'eth0')...")
    test_q = queue.Queue()
    capture_stop_event = threading.Event()
    
    # Using 'lo' for loopback interface for testing without needing external traffic or full sudo on some systems.
    # For capturing actual network traffic, 'eth0' (or your specific active interface) would be used.
    # If 'lo' doesn't show traffic, you might need to generate some (e.g., ping localhost).
    # The user needs to ensure 'tcpdump' is installed.
    # On a typical Linux system: sudo apt-get install tcpdump
    
    # Test with loopback interface 'lo'
    # If you have permission issues even with 'lo', it might be due to AppArmor/SELinux or other restrictions.
    # Running the script itself with `sudo python ids_capture.py` is the most straightforward way for tcpdump.
    interface_to_test = "lo" 
    print(f"Attempting to capture on interface: {interface_to_test}")
    print("If this hangs or shows errors, ensure tcpdump is installed and you have permissions.")
    print("You might need to run: 'sudo python ids_capture.py'")

    capture_thread = PacketCaptureThread(test_q, interface=interface_to_test, stop_event=capture_stop_event)
    capture_thread.start()

    try:
        # Let it run for a bit to capture some packets
        # Try pinging localhost in another terminal: ping -c 5 localhost
        print("Capture thread started. Listening for packets for up to 20 seconds...")
        print("Generate some traffic on the 'lo' interface (e.g., 'ping localhost') to see output.")
        
        for i in range(20): # Check queue every second for 20 seconds
            if not capture_thread.is_alive() and test_q.empty():
                print("Capture thread died unexpectedly and queue is empty.")
                break
            try:
                packet_dict = test_q.get(timeout=1) # Wait 1 second for a packet
                print(f"[{datetime.now()}] Got packet from queue: {packet_dict}")
            except queue.Empty:
                if i % 5 == 0: # Print a message every 5 seconds if queue is empty
                    print(f"Queue empty at {i+1}s, no packet received in the last second...")
            if capture_stop_event.is_set():
                print("Stop event was set externally during test loop.")
                break
        
        if not test_q.empty():
            print("Draining any remaining packets from queue after test loop...")
            while not test_q.empty():
                try:
                    packet_dict = test_q.get_nowait()
                    print(f"[{datetime.now()}] Drained packet: {packet_dict}")
                except queue.Empty:
                    break
        
    except KeyboardInterrupt:
        print("\nUser interrupted test with Ctrl+C.")
    finally:
        print("\nStopping capture thread from main test...")
        if not capture_stop_event.is_set():
            capture_stop_event.set()
        
        capture_thread.join(timeout=10) # Increased timeout for join
        if capture_thread.is_alive():
            print("Capture thread did not join cleanly. It might be stuck in the tcpdump process handling.")
        else:
            print("Capture thread joined successfully.")
        print("Packet capture test finished.")
