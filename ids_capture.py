import threading
import time
import queue
import subprocess
import re
from datetime import datetime, timezone

class PacketData:
    """
    Represents a single captured network packet's relevant information.
    """
    def __init__(self, timestamp, protocol, source_ip, destination_ip,
                 destination_port, flags=None, details="", severity="MEDIUM", source_port=None):
        self.timestamp = timestamp
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.flags = flags if flags is not None else {}
        self.details = details
        self.severity = severity

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
            "severity": self.severity,
            "details": self.details
        }

class PacketCaptureThread(threading.Thread):
    """
    A thread responsible for capturing network packets from a specified interface.
    It falls back to tcpdump.
    Captured and parsed packet data is put onto a shared queue for processing.
    """
    def __init__(self, data_queue, interface="wlp2s0", stop_event=None):
        super().__init__()
        self.setName(f"PacketCaptureThread-{interface}")
        self.data_queue = data_queue
        self.interface = interface
        self.stop_event = stop_event or threading.Event()

        print(f"{self.getName()}: Using tcpdump for packet capture on {self.interface}.")

    def parse_tcpdump_line(self, line):
        """
        Parses a single line of tcpdump output to extract packet information.
        """
        try:
            if not line.strip():
                return None

            parts = line.split()
            if len(parts) < 6:
                # print(f"[PARSE_FAIL] Not enough parts in line: {line.strip()}")
                return None

            ip_index = -1
            for i, part in enumerate(parts):
                if part in {"IP", "IP6"}:
                    ip_index = i
                    break

            if ip_index == -1:
                # print(f"[PARSE_FAIL] 'IP' or 'IP6' marker not found in line: {line.strip()}")
                return None

            timestamp_str = parts[0] + " " + parts[1]
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    print(f"[TIMESTAMP_PARSE_FAIL] Timestamp parse failed: {timestamp_str}. Using current time.")
                    timestamp = datetime.now(timezone.utc)

            timestamp = timestamp.replace(tzinfo=timezone.utc)

            protocol = None
            severity = "MEDIUM"
            source_ip, source_port = None, None
            dest_ip, dest_port = None, None
            flags = {}
            details = line.strip()

            def split_ip_port(ip_port_str):
                if ip_port_str.count('.') >= 4:  # Heuristic for IPv4.port
                    try:
                        ip, port_str = ip_port_str.rsplit('.', 1)
                        if port_str.isdigit():
                            return ip, int(port_str)
                        else:  # Port is not a number
                            return ip_port_str, None
                    except ValueError:
                        return ip_port_str, None
                return ip_port_str, None

            if ip_index + 1 < len(parts) and ip_index + 3 < len(parts):
                src_full = parts[ip_index + 1]
                dst_full = parts[ip_index + 3].rstrip(':')

                source_ip, source_port = split_ip_port(src_full)
                dest_ip, dest_port = split_ip_port(dst_full)

            if not source_ip or not dest_ip:
                # print(f"[PARSE_FAIL] Could not extract source/destination IP from: {line.strip()}")
                return None

            if "TCP" in line or any(f in line for f in ["Flags", " S ", " F ", " R ", " P ", " U ", " ack "]):
                protocol = "TCP"
                flag_match = re.search(r"Flags \[([a-zA-Z.]+)\]", line)

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
                    if flags.get('RST'):
                        severity = "HIGH"
                    elif flags.get('SYN') and not flags.get('ACK'):
                        severity = "MEDIUM"
                else:
                    flags = {
                        'SYN': ' S ' in line and ' ack ' not in line.lower(),
                        'FIN': ' F ' in line,
                        'RST': ' R ' in line,
                        'PSH': ' P ' in line,
                        'URG': ' U ' in line,
                        'ACK': ' ack ' in line.lower() or ' . ' in line
                    }
                    for key in ['SYN', 'FIN', 'RST', 'PSH', 'URG', 'ACK']:
                        flags.setdefault(key, False)

            elif "UDP" in line:
                protocol = "UDP"
                length_match = re.search(r"length (\d+)", line)
                if length_match and int(length_match.group(1)) > 1000:
                    severity = "HIGH"

            elif "ICMP" in line:
                protocol = "ICMP"
                icmp_match = re.search(r"ICMP (.*?),", line)
                if icmp_match:
                    details = f"ICMP {icmp_match.group(1)}"
                if "unreachable" in details.lower():
                    severity = "MEDIUM"

            if protocol:
                parsed_dest_port = 0
                if dest_port is not None:
                    if isinstance(dest_port, int):
                        parsed_dest_port = dest_port
                    elif isinstance(dest_port, str) and dest_port.isdigit():
                        parsed_dest_port = int(dest_port)

                parsed_source_port = None
                if source_port is not None:
                    if isinstance(source_port, int):
                        parsed_source_port = source_port
                    elif isinstance(source_port, str) and source_port.isdigit():
                        parsed_source_port = int(source_port)

                packet_data_obj = PacketData(
                    timestamp=timestamp, protocol=protocol,
                    source_ip=source_ip, source_port=parsed_source_port,
                    destination_ip=dest_ip, destination_port=parsed_dest_port,
                    flags=flags, severity=severity, details=details
                )
                return packet_data_obj

            # print(f"[PARSE_FAIL_PROTOCOL] No protocol determined for line: {line.strip()}")
            return None

        except Exception as e:
            print(f"[PARSER_EXCEPTION] Error parsing line '{line[:100]}...': {e}")
            import traceback
            traceback.print_exc()
            print(f"[PARSER_LINE] Original line: {line.strip()}")  # <-- AJOUTEZ CECI POUR LE DEBUG
            return None

    def run_tcpdump_capture(self):
        print(f"{self.getName()}: Starting tcpdump capture on interface '{self.interface}'...")
        cmd = [
            "sudo", "tcpdump", "-i", self.interface, "-l", "-n", "-tttt", "-s", "0",
            "tcp or udp or icmp"
        ]
        print(f"[TCPDUMP_CMD] Running command: {' '.join(cmd)}")
        process = None
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            print(f"{self.getName()}: Tcpdump process started (PID: {process.pid}) on '{self.interface}'.")

            for line in iter(process.stdout.readline, ''):
                if self.stop_event.is_set():
                    print(f"{self.getName()}: Stop event received, breaking tcpdump loop.")
                    break

                if line.strip():
                    packet_info = self.parse_tcpdump_line(line.strip())
                    if packet_info:
                        packet_dict = packet_info.to_dict()
                        print(f"[PACKET_QUEUED] {packet_dict}")  # <-- AJOUTEZ CECI POUR LE DEBUG
                        self.data_queue.put(packet_dict)

            if process.poll() is not None and not self.stop_event.is_set():
                print(f"{self.getName()}: Tcpdump process exited prematurely with code {process.returncode}.")
                stderr_output = process.stderr.read()
                if stderr_output:
                    print(f"{self.getName()} tcpdump stderr:\n{stderr_output}")

        except FileNotFoundError:
            print(f"{self.getName()}: ERROR - tcpdump command not found.")
            self.data_queue.put({"error": "tcpdump_not_found", "interface": self.interface})
        except PermissionError:
            print(f"{self.getName()}: ERROR - Permission denied for tcpdump. Run with sudo or set capabilities.")
            self.data_queue.put({"error": "tcpdump_permission_denied", "interface": self.interface})
        except Exception as e:
            print(f"{self.getName()}: ERROR during tcpdump capture: {e}")
            self.data_queue.put({"error": str(e), "interface": self.interface})
        finally:
            if process:
                if process.poll() is None:  # if process is still running
                    print(f"{self.getName()}: Terminating tcpdump process (PID: {process.pid})...")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        print(f"{self.getName()}: Tcpdump did not terminate gracefully, killing.")
                        process.kill()
                        process.wait()
                    print(f"{self.getName()}: Tcpdump process terminated.")
                else:
                    print(f"{self.getName()}: Tcpdump process (PID: {process.pid}) already exited (code {process.returncode}).")
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    remaining_stderr = process.stderr.read()
                    if remaining_stderr:
                        print(f"{self.getName()} remaining tcpdump stderr:\n{remaining_stderr}")
                    process.stderr.close()
            print(f"{self.getName()}: Tcpdump capture process for '{self.interface}' stopped.")

    def run(self):
        print(f"{self.getName()}: Starting packet capture on '{self.interface}'")
        self.run_tcpdump_capture()
        print(f"{self.getName()}: Finished run method. Thread will exit.")

    def stop(self):
        print(f"{self.getName()}: Stopping packet capture thread for '{self.interface}'...")
        self.stop_event.set()

if __name__ == '__main__':
    print("Starting packet capture test (sudo might be required)...")
    test_q = queue.Queue()
    capture_stop_event = threading.Event()

    interface_to_test = "wlp2s0"  # Change to your actual interface
    print(f"Attempting capture on: {interface_to_test}")
    print("To generate test traffic (from another terminal):")
    print(f"  ping -c 3 <IP de {interface_to_test}>")
    print(f"  sudo nmap -sS -p 80,443 <IP de {interface_to_test}>")

    capture_thread = PacketCaptureThread(test_q, interface=interface_to_test, stop_event=capture_stop_event)
    capture_thread.start()
    print(f"Capture thread started: {capture_thread.is_alive()}")

    packet_count = 0
    try:
        print("Listening for packets for up to 30 seconds... (Ctrl+C to stop early)")
        while not capture_stop_event.is_set():
            if not capture_thread.is_alive() and test_q.empty():
                print("Capture thread died and queue is empty.")
                break
            try:
                packet_dict = test_q.get(timeout=1)  # Increased timeout
                packet_count += 1
                print(f"[{datetime.now().time()}] MainTest - Packet #{packet_count}: {packet_dict.get('source_ip','N/A')}:{packet_dict.get('source_port','N/A')} -> {packet_dict.get('destination_ip','N/A')}:{packet_dict.get('destination_port','N/A')} [{packet_dict.get('protocol','N/A')}] Flags: {packet_dict.get('flags',{})}")
            except queue.Empty:
                print(f"Queue empty at {datetime.now().time()}, waiting for packets...")
            except KeyboardInterrupt:
                print("\nUser interrupted test.")
                capture_stop_event.set()
                break
            time.sleep(0.1)  # Small delay

        print(f"\nTotal packets processed by main test loop: {packet_count}")

    finally:
        print("\nStopping capture thread from main test...")
        if not capture_stop_event.is_set():
            capture_stop_event.set()

        capture_thread.join(timeout=10)
        if capture_thread.is_alive():
            print("Capture thread did not join cleanly!")
        else:
            print("Capture thread joined successfully.")

        # Drain queue after thread stop
        remaining_in_queue = 0
        while not test_q.empty():
            try:
                test_q.get_nowait()
                remaining_in_queue += 1
            except queue.Empty:
                break
        if remaining_in_queue > 0:
            print(f"Drained {remaining_in_queue} additional packets from queue after thread stop.")

        print("Packet capture test finished.")