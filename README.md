# WaspIDS - Hybrid Intrusion Detection System

WaspIDS is a prototype Hybrid Intrusion Detection System that combines signature-based detection techniques with machine learning-powered anomaly detection to identify and flag suspicious network activity. This backend is built with Flask and uses various tools for packet capture, analysis, and logging.

## Hybrid IDS Backend Setup and Usage

This section describes how to set up and run the WaspIDS backend components.

### Prerequisites

*   **Python:** Version 3.8+ is recommended.
*   **PostgreSQL Server:** An instance of PostgreSQL must be installed and running.
*   **`tcpdump`:** This utility is required for packet capture. Install it via your system's package manager:
    ```bash
    sudo apt-get update && sudo apt-get install tcpdump
    ```
*   **(Optional but recommended) Python Virtual Environment:** Tools like `virtualenv` or the built-in `venv` module are recommended to manage project dependencies.

### Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create and Activate Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate 
    ```
    (On Windows, use `venv\Scripts\activate`)

3.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *   **Note on `netifaces` / `python-libpcap`:** The system uses `tcpdump` (a system utility) for packet capture, invoked via a subprocess. Previous development steps indicated persistent issues with installing Python libraries `netifaces` and `python-libpcap` in some environments. These are not strictly required if `tcpdump` is installed system-wide, and `requirements.txt` should reflect the minimal working set (primarily Flask, SQLAlchemy, mljar-supervised, and their dependencies).

4.  **Database Setup:**
    *   Ensure your PostgreSQL server is actively running.
    *   Connect to your PostgreSQL server and create a new database. For example:
        ```sql
        CREATE DATABASE wasp_ids;
        ```
    *   Create a user and grant it privileges to the database. For example:
        ```sql
        CREATE USER vivien WITH PASSWORD 'vivien';
        GRANT ALL PRIVILEGES ON DATABASE wasp_ids TO vivien;
        ```
    *   **Update Connection URI:** The application expects the database connection URI at `SQLALCHEMY_DATABASE_URI` in `app.py`. The default is `postgresql+psycopg2://vivien:vivien@localhost:5432/wasp_ids`. If your database name, user, password, host, or port differ, update this string accordingly.
    *   **Table Creation:** The necessary tables (`users`, `ids_logs`) will be created automatically by the application when it runs for the first time.

5.  **Training Data for ML Module:**
    *   Prepare your training dataset as a CSV file named `training_data.csv` and place it in the root directory of the project.
    *   The expected columns in this CSV file are: `Header_Length,Protocol Type,Time_To_Live,Rate,fin_flag_number,syn_flag_number,rst_flag_number,psh_flag_number,ack_flag_number,ece_flag_number,cwr_flag_number,ack_count,syn_count,fin_count,rst_count,HTTP,HTTPS,DNS,Telnet,SMTP,SSH,IRC,TCP,UDP,DHCP,ARP,ICMP,IGMP,IPv,LLC,Tot sum,Min,Max,AVG,Std,Tot size,IAT,Number,Variance,is_anomaly`. The `is_anomaly` column is the target variable (0 for normal, 1 for anomaly).
    *   Run the ML training script from the project root:
        ```bash
        python ml_trainer.py
        ```
        This script will use `mljar-supervised` to train models. It will create:
        *   `anomaly_detection_config.json`: Contains metadata about the training run, including the path to MLJAR results.
        *   `mljar_results/`: A directory containing detailed reports, models, and logs from the MLJAR training process. (This directory is added to `.gitignore`).

### Running the Application

1.  **Network Interface Configuration:**
    *   The packet capture script (`packet_capturer.py`) defaults to listening on the network interface `wlp2s0`. This is a common name for wireless interfaces on Linux systems.
    *   **Important:** If your system uses a different interface name (e.g., `eth0`, `en0`, `lo` for loopback, or `any` to capture on all interfaces), you **must** modify the `INTERFACE` variable at the top of `packet_capturer.py` before running the application. Using `any` can be very verbose and capture a lot of traffic.

2.  **Start the Flask App with Integrated IDS:**
    Open your terminal in the project root (with the virtual environment activated) and run:
    ```bash
    sudo python app.py
    ```
    *   **`sudo` Requirement:** Root privileges are necessary because `tcpdump` (which is executed by `packet_capturer.py`) requires elevated permissions to capture network traffic.
    *   The application starts the Flask development server. By default, it runs in debug mode. `use_reloader=False` is set in `app.py` to ensure proper operation of the IDS background thread.
    *   The IDS components (packet capture and detection engine) will start in a background thread. You should see log messages in the console indicating their status.

3.  **Access the Application:**
    *   Once running, the web application is typically accessible at `http://127.0.0.1:5000/` in your web browser.
    *   Features like the log API (`/api/logs`) require user authentication.

### Stopping the Application

*   To stop the Flask application and the IDS background thread, press `Ctrl+C` in the terminal where `app.py` is running.
*   The IDS thread is configured as a daemon, so it will automatically terminate when the main application (Flask server) shuts down.

### Troubleshooting

*   **Permission Denied for `tcpdump`:** If `packet_capturer.py` reports a permission error, ensure you are running `app.py` with `sudo` as shown in the run command.
*   **`psycopg2` Errors (Database Connection Issues):**
    *   Verify that your PostgreSQL server is running and accessible.
    *   Double-check the `SQLALCHEMY_DATABASE_URI` in `app.py` to ensure it correctly points to your database with valid credentials.
    *   Confirm that the `psycopg2-binary` package was installed correctly from `requirements.txt`.
*   **MLJAR Training Errors:**
    *   Ensure `mljar-supervised` and its dependencies were installed correctly.
    *   Verify the `training_data.csv` file exists in the project root and that its format and columns match the expected structure. Check for any missing or incorrectly named columns.
*   **"Address already in use" for Flask App:** This means another process is using port 5000. Stop the other process or run Flask on a different port (e.g., `app.run(debug=True, use_reloader=False, port=5001)`).
*   **Interface Not Found by `tcpdump`:** If `tcpdump` (via `packet_capturer.py`) fails to start and mentions an interface issue, confirm the `INTERFACE` variable in `packet_capturer.py` is set to a valid and active network interface on your system.
