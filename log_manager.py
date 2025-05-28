# This file will handle logging of IDS events and alerts.
# It will interact with the IDSLog model and the database.

from app import IDSLog, db # Assuming app.py contains IDSLog model and db instance
from datetime import datetime, timezone

def save_alert_to_db(alert_data: dict, app_instance):
    """
    Saves a detected alert to the database.

    Args:
        alert_data (dict): A dictionary containing the alert information.
                           Expected keys: 'timestamp', 'source_ip', 'destination_ip',
                                          'source_port', 'destination_port', 'protocol',
                                          'scan_type', 'severity', 'details'.
        app_instance: The Flask application instance.
    """
    if not isinstance(alert_data, dict):
        print("LogManager: Error - alert_data must be a dictionary.")
        return False

    required_fields = ['timestamp', 'source_ip', 'destination_ip', 'protocol', 'scan_type', 'severity', 'details']
    for field in required_fields:
        if field not in alert_data:
            print(f"LogManager: Error - Missing required field '{field}' in alert_data.")
            return False
            
    if not hasattr(app_instance, 'app_context'):
        print("LogManager: Error - app_instance does not have 'app_context'. Make sure a Flask app instance is passed.")
        return False

    try:
        with app_instance.app_context():
            # Ensure timestamp is a datetime object, ideally UTC
            # The detection_engine should provide this as a datetime object already.
            alert_timestamp = alert_data['timestamp']
            if not isinstance(alert_timestamp, datetime):
                print(f"LogManager: Warning - Timestamp '{alert_timestamp}' is not a datetime object. Attempting to parse.")
                # Attempt to parse if it's a string, assuming ISO format. This is a fallback.
                try:
                    alert_timestamp = datetime.fromisoformat(str(alert_timestamp).replace('Z', '+00:00'))
                except ValueError:
                    print(f"LogManager: Error - Could not parse timestamp '{alert_timestamp}'. Using current UTC time.")
                    alert_timestamp = datetime.now(timezone.utc)
            
            # Ensure it's timezone-aware (UTC)
            if alert_timestamp.tzinfo is None:
                alert_timestamp = alert_timestamp.replace(tzinfo=timezone.utc)


            log_entry = IDSLog(
                timestamp=alert_timestamp,
                source_ip=alert_data['source_ip'],
                destination_ip=alert_data['destination_ip'],
                source_port=alert_data.get('source_port'), # Use .get for optional fields
                destination_port=alert_data.get('destination_port'),
                protocol=alert_data['protocol'],
                scan_type=alert_data['scan_type'],
                severity=alert_data['severity'],
                details=alert_data['details']
            )
            db.session.add(log_entry)
            db.session.commit()
            print(f"LogManager: Alert saved successfully to database. Log ID: {log_entry.id}")
            return True
    except Exception as e:
        db.session.rollback()
        print(f"LogManager: Error saving alert to database: {e}")
        # For more detailed debugging, you might want to log the full traceback
        # import traceback
        # traceback.print_exc()
        return False

if __name__ == '__main__':
    # This block demonstrates how to test save_alert_to_db with a minimal Flask app.
    from flask import Flask
    
    print("LogManager: Running standalone test...")

    # Create a minimal Flask app for testing
    test_app = Flask(__name__)
    test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # Use in-memory SQLite
    test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    test_app.config['TESTING'] = True

    # Initialize SQLAlchemy with the test app
    # We need to associate db with this specific app instance for the test
    # If db from app.py is already bound to the main app, this can be tricky.
    # A better pattern for testability is to have db initialized in a way it can be
    # re-associated or to pass db instance directly to log_manager functions.
    # For this test, we assume we can re-init db with our test_app.
    # This might not work if app.db is already configured and used by other imports.
    # A common pattern is `db.init_app(test_app)` if db was created as `SQLAlchemy()`.
    
    # Since app.db is already created as SQLAlchemy(app) in app.py,
    # directly re-binding it here is problematic.
    # A cleaner way would be for log_manager to not directly import 'db' from 'app',
    # but to receive 'db' and 'IDSLog' as parameters or have a LogManager class.
    # Given the current structure, we'll try to make it work by re-assigning `app` for `db`.
    
    # This is a workaround for the current structure:
    original_app_for_db = db.app # Save original app if it exists
    db.init_app(test_app) # Associate db with our test_app

    with test_app.app_context():
        db.create_all() # Create tables, including IDSLog

        print("LogManager Test: Database and tables created in memory.")

        # Test Case 1: Valid Alert
        valid_alert = {
            "timestamp": datetime.now(timezone.utc), # Already a datetime object
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200",
            "source_port": 12345,
            "destination_port": 80,
            "protocol": "TCP",
            "scan_type": "SYN Scan",
            "severity": "Medium",
            "details": "Test SYN scan detected from 192.168.1.100"
        }
        print(f"\nLogManager Test: Attempting to save valid alert: {valid_alert}")
        success = save_alert_to_db(valid_alert, test_app)
        print(f"LogManager Test: Save successful: {success}")

        if success:
            # Verify entry in DB
            log_entries = IDSLog.query.all()
            print(f"LogManager Test: Found {len(log_entries)} log entries in DB.")
            if log_entries:
                print(f"LogManager Test: First entry - ID: {log_entries[0].id}, Source IP: {log_entries[0].source_ip}, Details: {log_entries[0].details}")
                assert len(log_entries) == 1
                assert log_entries[0].source_ip == "192.168.1.100"
            else:
                print("LogManager Test: Error - No entries found after successful save call.")
        
        # Test Case 2: Alert with missing required field
        invalid_alert_missing_field = {
            "timestamp": datetime.now(timezone.utc),
            "source_ip": "10.0.0.1",
            # 'destination_ip' is missing
            "protocol": "UDP",
            "scan_type": "UDP Scan",
            "severity": "Low",
            "details": "Test UDP scan with missing field"
        }
        print(f"\nLogManager Test: Attempting to save alert with missing field: {invalid_alert_missing_field}")
        success_invalid_missing = save_alert_to_db(invalid_alert_missing_field, test_app)
        print(f"LogManager Test: Save successful (should be False): {success_invalid_missing}")
        assert not success_invalid_missing

        # Test Case 3: Alert with non-datetime timestamp (string)
        alert_string_ts = {
            "timestamp": "2024-05-29T10:30:00Z", # String timestamp
            "source_ip": "172.16.0.5",
            "destination_ip": "172.16.0.10",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "scan_type": "Port Sweep",
            "severity": "High",
            "details": "Test port sweep with string timestamp"
        }
        print(f"\nLogManager Test: Attempting to save alert with string timestamp: {alert_string_ts}")
        success_string_ts = save_alert_to_db(alert_string_ts, test_app)
        print(f"LogManager Test: Save successful: {success_string_ts}")
        if success_string_ts:
             log_entries_str_ts = IDSLog.query.filter_by(source_ip="172.16.0.5").all()
             assert len(log_entries_str_ts) == 1
             print(f"LogManager Test: Found entry for string_ts test: {log_entries_str_ts[0].details}")


        # Clean up: drop all tables after test
        db.drop_all()
        print("\nLogManager Test: Database tables dropped.")

    # Restore db's original app if necessary
    if original_app_for_db:
        db.init_app(original_app_for_db)
    
    print("\nLogManager: Standalone test finished.")
