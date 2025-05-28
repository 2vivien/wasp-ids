import subprocess
from datetime import datetime, timezone
import re
import sys # For flushing output

# Define the target interface (hardcoded as netifaces is unavailable)
# TODO: Replace with dynamic interface detection if netifaces or similar becomes available
INTERFACE = "wlp2s0" # Common name for wireless interfaces, but may vary.
# For testing in environments where wlp2s0 might not exist,
# consider using "any" or "lo" if appropriate, but "any" can be very verbose.
# INTERFACE = "any" # Example: use "any" for all interfaces, requires appropriate permissions

def parse_tcpdump_line(line_str: str) -> dict | None:
    """
    Parses a single line of tcpdump output.

    Expected tcpdump format (-tttt -n -l):
    YYYY-MM-DD HH:MM:SS.ffffff IP [source_ip].[source_port] > [dest_ip].[dest_port]: Flags [flags], seq ..., ack ..., win ..., options ..., length ...
    YYYY-MM-DD HH:MM:SS.ffffff IP6 [source_ip].[source_port] > [dest_ip].[dest_port]: Flags [flags], ...
    YYYY-MM-DD HH:MM:SS.ffffff ARP, Request who-has [target_ip] tell [sender_ip], length ...
    YYYY-MM-DD HH:MM:SS.ffffff ICMP [source_ip] > [dest_ip]: echo request, ...

    Returns a dictionary with parsed fields or None if parsing fails.
    """
    line_str = line_str.strip()
    if not line_str:
        return None

    # General pattern for IP packets (TCP/UDP/ICMP)
    # It captures timestamp, protocol (IP/IP6), src/dst IPs and ports, and flags for TCP
    # Example TCP: 2024-05-28 15:10:30.123456 IP 192.168.1.10.54321 > 192.168.1.20.80: Flags [S.], seq 123, ack 0, win 65535, options [mss 1460,sackOK,TS val 10 ecr 0,nop,wscale 7], length 0
    # Example UDP: 2024-05-28 15:10:30.234567 IP 10.0.0.5.123 > 10.0.0.6.53: 1+ A? example.com. (30)
    # Example ICMP: 2024-05-28 15:10:30.345678 IP 172.16.0.1 > 172.16.0.2: ICMP echo request, id 1, seq 1, length 64
    ip_pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+"  # Timestamp
        r"(?P<l2_proto>IP6?)\s+"                                         # L2 Proto (IP or IP6)
        r"(?P<source_ip>[\w.:-]+?)"                                     # Source IP (allow for IPv6, hostnames if -n not fully effective)
        r"(?:\.(?P<source_port>\d+))?"                                  # Optional Source Port
        r"\s+>\s+"
        r"(?P<destination_ip>[\w.:-]+?)"                               # Destination IP
        r"(?:\.(?P<destination_port>\d+))?:"                            # Optional Destination Port
        r"(?:\s+Flags\s+\[(?P<flags>[^\]]+)\],)?"                       # Optional TCP Flags
        r".*?\s+(?P<protocol>TCP|UDP|ICMP|ICMPv6)"                      # Protocol (deduced later if not here)
    )

    # More specific patterns if the general one is too broad or misses cases
    # This simplified pattern tries to capture the protocol from the end part if possible
    # and handles cases where flags might not be present or ports are not applicable (e.g. ICMP)
    packet_re = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+" # Timestamp YYYY-MM-DD HH:MM:SS.ffffff
        r"IP6?\s+"                                                       # IP or IP6
        r"(?P<source_ip>[\w.:-]+?)"                                     # Source IP (allow for IPv6 or hostnames if -n not fully effective)
        r"(?:\.(?P<source_port>\d+))?"                                  # Optional Source Port for TCP/UDP
        r"\s+>\s+"
        r"(?P<destination_ip>[\w.:-]+?)"                               # Destination IP
        r"(?:\.(?P<destination_port>\d+))?:"                            # Optional Destination Port for TCP/UDP
        r"(?:.*?Flags\s+\[(?P<tcp_flags>[^\]]+)\],)?"                   # Optional TCP Flags (e.g., [S.], [P.], [F.], [R.])
        r".*?(?P<protocol_guess>TCP|UDP|ICMPv?6?)(?:,|\s|$)"            # Protocol guess (TCP, UDP, ICMP, ICMP6, ICMPv6)
    )
    
    # ARP pattern
    # Example: 2024-05-28 15:10:30.456789 ARP, Request who-has 192.168.1.1 tell 192.168.1.100, length 46
    arp_pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+"
        r"ARP,\s+"
        r"(?:Request who-has\s+(?P<arp_target_ip>[\w.:-]+)\s+tell\s+(?P<arp_sender_ip>[\w.:-]+)|" # Request
        r"Reply\s+(?P<arp_is_at_ip>[\w.:-]+)\s+is-at\s+[\w:]+)"                                   # Reply
    )

    match = packet_re.match(line_str)
    if match:
        data = match.groupdict()
        try:
            dt_obj = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
            dt_obj_utc = dt_obj.replace(tzinfo=timezone.utc) # Assume local time is UTC as per tcpdump -tttt
        except ValueError:
            # If timestamp parsing fails, this line is likely not a valid packet entry
            return None

        # Normalize TCP flags
        raw_flags = data.get('tcp_flags')
        normalized_flags = None
        if raw_flags:
            # Common flags: S (SYN), P (PSH), F (FIN), R (RST), . (ACK)
            # We want to make them more readable, e.g., S. -> SA (SYN-ACK), P. -> PA (PSH-ACK)
            # Order: S F R P A U E C (standard order for display)
            flags_present = []
            if 'S' in raw_flags: flags_present.append('S')
            if 'F' in raw_flags: flags_present.append('F')
            if 'R' in raw_flags: flags_present.append('R')
            if 'P' in raw_flags: flags_present.append('P')
            if '.' in raw_flags: flags_present.append('A') # ACK
            # Less common, but good to note
            if 'U' in raw_flags: flags_present.append('U') # URG
            if 'E' in raw_flags: flags_present.append('E') # ECE
            if 'C' in raw_flags: flags_present.append('C') # CWR
            
            normalized_flags = "".join(flags_present) if flags_present else None


        return {
            "timestamp": dt_obj_utc,
            "source_ip": data['source_ip'],
            "destination_ip": data['destination_ip'],
            "source_port": int(data['source_port']) if data['source_port'] else None,
            "destination_port": int(data['destination_port']) if data['destination_port'] else None,
            "protocol": data['protocol_guess'].upper().replace("V6",""), # Normalize ICMPV6 to ICMP
            "flags": normalized_flags
        }

    arp_match = arp_pattern.match(line_str)
    if arp_match:
        data = arp_match.groupdict()
        try:
            dt_obj = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
            dt_obj_utc = dt_obj.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        
        # For ARP, source/destination IP depends on request/reply type
        source_ip = data.get('arp_sender_ip')
        dest_ip = data.get('arp_target_ip')
        if not source_ip and data.get('arp_is_at_ip'): # This is a reply, the "is_at_ip" is the source
            # In an ARP reply "X is at MAC", X is the source_ip in the context of who is providing info
            # However, tcpdump output for reply "192.168.1.1 is-at aa:bb:cc:dd:ee:ff"
            # Here, 192.168.1.1 is effectively the "source" of the information.
            # The "destination" is implicit (the requester). For simplicity, we'll use what's available.
            source_ip = data.get('arp_is_at_ip')
            dest_ip = "Broadcast" # ARP replies are often broadcast or to a specific MAC not easily parsed here

        return {
            "timestamp": dt_obj_utc,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": None,
            "destination_port": None,
            "protocol": "ARP",
            "flags": None
        }
    
    # If the line is a tcpdump startup/shutdown message or unparsed
    if "listening on" in line_str or "bytes captured" in line_str or "packets captured" in line_str:
        print(f"Ignoring tcpdump message: {line_str}", file=sys.stderr)
        return None

    print(f"Unparsed line: {line_str}", file=sys.stderr)
    return None


def start_capture(callback_function):
    """
    Starts packet capture using tcpdump and processes each packet line.
    """
    # Command: sudo tcpdump -i <interface> -l -n -tttt
    # -l: Line buffer output (essential for real-time processing)
    # -n: Don't convert addresses (IPs, ports) to names
    # -tttt: Timestamp in YYYY-MM-DD HH:MM:SS.ffffff format
    # Adding -q to reduce some verbosity, focusing on packet data
    # tcpdump_command = ['sudo', 'tcpdump', '-i', INTERFACE, '-l', '-n', '-tttt', '-q']
    # Sticking to original request flags
    tcpdump_command = ['sudo', 'tcpdump', '-i', INTERFACE, '-l', '-n', '-tttt']
    
    print(f"Starting capture on interface {INTERFACE} with command: {' '.join(tcpdump_command)}", file=sys.stderr)
    
    try:
        # Using Popen to manage the subprocess
        process = subprocess.Popen(tcpdump_command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True, # Decodes stdout/stderr as text
                                   bufsize=1) # Line buffered

        print("tcpdump process started. Waiting for output...", file=sys.stderr)

        # Read output line by line
        for line in iter(process.stdout.readline, ''):
            if not line: # Should not happen with iter readline unless process ends
                break
            parsed_data = parse_tcpdump_line(line)
            if parsed_data:
                callback_function(parsed_data)
            sys.stdout.flush() # Ensure data is sent to parent if any

        # Check for errors after process ends
        stderr_output = process.stderr.read()
        if stderr_output:
            print(f"tcpdump stderr: {stderr_output}", file=sys.stderr)
        
        process.stdout.close()
        process.stderr.close()
        process.wait()

    except FileNotFoundError:
        print(f"Error: tcpdump command not found. Please ensure tcpdump is installed and in PATH.", file=sys.stderr)
    except PermissionError:
        print(f"Error: Permission denied. tcpdump typically requires root privileges. Try running with sudo.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred during packet capture: {e}", file=sys.stderr)
    finally:
        print("Packet capture stopped.", file=sys.stderr)

# Example callback function
def my_callback(packet_data):
    """
    Example callback function to process parsed packet data.
    """
    print(packet_data)

if __name__ == '__main__':
    print("Starting packet capturer script directly for testing...", file=sys.stderr)
    # Note: This script needs to be run with sudo for tcpdump to work.
    # Example: sudo python packet_capturer.py
    # The 'sudo' is also included in the tcpdump_command list.
    
    # Check if INTERFACE is set to "wlp2s0" and provide a warning if so,
    # as it's unlikely to exist in many test environments.
    if INTERFACE == "wlp2s0":
        print(f"Warning: INTERFACE is set to '{INTERFACE}'. This interface may not exist on your system.", file=sys.stderr)
        print("You might need to change it to an active interface (e.g., 'eth0', 'en0', 'any', or 'lo').", file=sys.stderr)
        print("If using 'any', be aware it captures on all interfaces and can be very verbose.", file=sys.stderr)

    start_capture(my_callback)

# Placeholder for ml_trainer.py (This line was in the original template, removing as it's not relevant here)
# (Placeholder for packet_capturer.py) # This was also in the original template
# This file will be responsible for capturing network packets.
# It will use python-libpcap and netifaces to achieve this. # Updated: Will use tcpdump via subprocess
# Further details will be added as the project progresses.
# (Placeholder for detection_engine.py) # Removing
# (Placeholder for log_manager.py) # Removing
