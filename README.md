# WASP - Port Scan IDS Backend

## Overview

This project implements a Flask-based backend system for detecting various types of port scans on a network. It includes components for offline machine learning model training (for potential rule/threshold derivation), real-time packet capture, a signature-based detection engine, alert logging to a PostgreSQL database, and a REST API for retrieving logged alerts.

## Features

*   **Offline ML Training:** A script (`train_mljar.py`) using MLJAR-Supervised for automated machine learning to analyze network traffic data. This can be used to derive or fine-tune rules and thresholds for the detection engine (this part is for offline analysis and model building, not directly integrated into the real-time engine's decision making in this version).
*   **Real-time Packet Capture:** Captures network packets on a specified interface. Currently uses `tcpdump` as the capture mechanism. (The original intention was to use PF_RING for high-performance capture, which could be a future enhancement).
*   **Signature-Based Detection Engine:** The `ids_engine.py` module analyzes captured packets to detect common port scan techniques, including:
    *   SYN Scan (high rate to a single port)
    *   SYN Scan (targeting multiple ports on a single destination)
    *   Horizontal Scan (targeting multiple IPs on the same port or various ports)
    *   No-Response Scan (detecting probes to ports that don't respond)
*   **Alert Logging:** Detected scan events are logged as alerts into a PostgreSQL database (`port_scan_logs` table).
*   **REST API for Alerts:** A Flask endpoint (`/api/logs`) allows authenticated users to retrieve logged alerts in JSON format.

## Project Structure

*   `app.py`: The main Flask application file. It handles user authentication, web interface routing, API endpoints, and integrates the IDS components.
*   `ids_capture.py`: Module responsible for capturing network packets using `tcpdump`.
*   `ids_engine.py`: Module containing the logic for detecting port scans based on predefined signatures and rules.
*   `train_mljar.py`: Python script for training an ML model using MLJAR-Supervised on a network traffic dataset (CSV format).
*   `requirements.txt`: Lists all Python dependencies.
*   `network_traffic_dataset.csv`: A placeholder CSV file for `train_mljar.py`. Users should replace this with their actual dataset.
*   `static/` & `templates/`: Directories for Flask web interface assets (CSS, JS, HTML).

## Setup and Dependencies

1.  **Python:** Python 3.x is required.
2.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    This will install Flask, SQLAlchemy, MLJAR-Supervised, Pandas, and other necessary libraries.
3.  **`tcpdump`:**
    *   **Crucial:** `tcpdump` must be installed on your system and accessible in the system's PATH. The packet capture module (`ids_capture.py`) relies on it.
    *   To install on Debian/Ubuntu: `sudo apt-get update && sudo apt-get install tcpdump`
    *   Note: The original project request specified PF_RING for packet capture. Due to potential complexities in its setup and to ensure broader compatibility, `tcpdump` is used as the current packet capture mechanism. PF_RING integration remains a potential future enhancement for higher performance.
4.  **PostgreSQL Database:**
    *   A PostgreSQL server must be running.
    *   The application is configured to connect to a database named `wasp_ids` with user `vivien` and password `vivien`.
    *   Connection URI in `app.py`: `postgresql+psycopg2://vivien:vivien@localhost:5432/wasp_ids`
    *   **Basic PostgreSQL Setup (Example for Ubuntu):**
        ```bash
        sudo apt-get install postgresql postgresql-contrib
        sudo -u postgres psql
        # Inside psql:
        CREATE DATABASE wasp_ids;
        CREATE USER vivien WITH PASSWORD 'vivien';
        GRANT ALL PRIVILEGES ON DATABASE wasp_ids TO vivien;
        ALTER ROLE vivien CREATEDB; # Optional, gives user ability to create DBs
        \q 
        ```
        Ensure your PostgreSQL server is configured to allow connections from `localhost` for the `vivien` user (e.g., check `pg_hba.conf`).

## Running the MLJAR Training Script (Offline Analysis)

The `train_mljar.py` script is for offline analysis of network traffic data to potentially derive or fine-tune detection rules and thresholds.

1.  **Prepare your dataset:** You need a CSV file containing network traffic data. The last column is assumed to be the target variable (e.g., indicating if a row represents an attack or normal traffic). A placeholder file `network_traffic_dataset.csv` is provided; replace it with your actual data.
2.  **Run the script:**
    ```bash
    python train_mljar.py --csv_path path/to/your/dataset.csv --results_path output_folder_for_mljar_results
    ```
    *   `--csv_path`: Path to your input CSV dataset.
    *   `--results_path`: Folder where MLJAR AutoML will save its results (leaderboards, model files, explanations).

## Running the Flask Application (IDS Backend)

1.  **Ensure PostgreSQL is running and configured as per the "Setup" section.**
2.  **Open your terminal and navigate to the project root directory.**
3.  **Start the application:**
    ```bash
    python app.py
    ```
    This will start the Flask development server (usually on `http://127.0.0.1:5000/`) and initialize the background IDS packet capture and detection engine threads.

4.  **Configuration Notes:**
    *   **Capture Interface:**
        *   The network interface for packet capture is configured in `app.py` within the `start_ids_threads` function:
            `capture_interface = app.config.get('CAPTURE_INTERFACE', 'lo')`
        *   It defaults to `'lo'` (loopback interface), which is suitable for local testing.
        *   To monitor actual network traffic, change `'lo'` to your desired network interface (e.g., `'eth0'`, `'enp3s0'`). You might need to check your system's interface names (e.g., using `ip addr` or `ifconfig`).
    *   **Root Privileges for Packet Capture:**
        *   Capturing packets on most network interfaces (like `'eth0'`) with `tcpdump` typically requires root privileges.
        *   If you are capturing on such an interface, you may need to run the Flask application with `sudo`:
            ```bash
            sudo python app.py
            ```
        *   Alternatively, you can grant specific capabilities to `tcpdump` (e.g., `sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump`) to allow it to be run by non-root users, but this has security implications and should be done with caution.

## Testing the IDS

Once the Flask application is running (including the IDS threads):

1.  **Generate Scan Traffic:**
    Use tools like `nmap` to generate port scan traffic on the interface the IDS is monitoring (default is `localhost` for the `'lo'` interface).
    *   **Example (run in a separate terminal): SYN Scan on localhost**
        ```bash
        # Scan ports 1-100 on localhost
        sudo nmap -sS -p 1-100 localhost 
        ```
    *   **Example: Fast SYN Scan on a single port on localhost**
        ```bash
        sudo nmap -sS -p 80 -n -PN --min-rate 100 --max-retries 0 localhost
        ```
    *   **Example: Probing closed/filtered ports on localhost (for No Response Scan)**
        ```bash
        sudo nmap -sS -p 10000-10100 -n -PN --max-retries 0 localhost 
        ```
    **(Ensure `nmap` is installed: `sudo apt-get install nmap`)**

2.  **Viewing Alerts:**
    *   **Web API:**
        1.  Register a user via the application's web interface (e.g., `http://127.0.0.1:5000/registration`).
        2.  Log in with the registered user (e.g., `http://127.0.0.1:5000/login`).
        3.  Navigate to `http://127.0.0.1:5000/api/logs` in your browser. You should see a JSON response containing the logged alerts.
    *   **Database:**
        Connect to your PostgreSQL database (`wasp_ids`) and query the `port_scan_logs` table:
        ```sql
        SELECT * FROM port_scan_logs ORDER BY timestamp DESC;
        ```
    *   **Console Output:**
        The terminal running `python app.py` will print "ALERT Logged to DB: ..." messages when the IDS detects and logs a scan.

## Current Limitations / Future Work

*   **Packet Capture Mechanism:** Packet capture currently uses `tcpdump`. While widely available, PF_RING integration (as originally requested) could be pursued for higher performance packet capture, especially in high-traffic environments.
*   **Detection Rule Configuration:** Detection rule thresholds and time windows are currently hardcoded in `ids_engine.py`. Future enhancements could involve making these configurable via a configuration file or a settings interface in the application.
*   **ML Model Integration:** The `train_mljar.py` script provides offline ML capabilities. Integrating a trained model for real-time anomaly detection or adaptive thresholding into the `ids_engine.py` would be a significant enhancement.
*   **Scalability:** For production use on high-bandwidth networks, further optimizations for performance and scalability of the capture and detection engine would be necessary. This might include exploring asynchronous processing more deeply or using more specialized stream processing frameworks.
*   **Error Handling & Robustness:** While basic error handling is present, further hardening of the IDS threads and inter-thread communication would improve robustness.
