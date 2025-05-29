# This file will handle logging of IDS events and alerts.
# It will interact with the IDSLog model and the database.

from app import IDSLog, db  # Assuming app.py contains IDSLog model and db instance
from datetime import datetime, timezone
from flask import current_app


def save_alert_to_db(alert_data: dict, db_instance, IDSLog_model):
    """
    Saves a detected alert to the database.

    Args:
        alert_data (dict): A dictionary containing the alert information.
                           Expected keys: 'timestamp', 'source_ip', 'destination_ip',
                                          'source_port', 'destination_port', 'protocol',
                                          'scan_type', 'severity', 'details'.
        db_instance: The SQLAlchemy database instance.
        IDSLog_model: The IDSLog model class.
    """
    if not isinstance(alert_data, dict):
        print("LogManager: Error - alert_data must be a dictionary.")
        return False

    required_fields = ['timestamp', 'source_ip', 'destination_ip', 'protocol', 'scan_type', 'severity', 'details']
    for field in required_fields:
        if field not in alert_data:
            print(f"LogManager: Error - Missing required field '{field}' in alert_data.")
            return False

    try:
        # Ensure timestamp is a datetime object (convert if necessary)
        if isinstance(alert_data['timestamp'], str):
            try:
                alert_data['timestamp'] = datetime.fromisoformat(alert_data['timestamp'].replace("Z", "+00:00"))
            except ValueError:
                print("LogManager: Error - Invalid timestamp format. Expected ISO format.")
                return False
        elif not isinstance(alert_data['timestamp'], datetime):
            print("LogManager: Error - Timestamp must be a datetime object or a string in ISO format.")
            return False

        new_alert = IDSLog_model(
            timestamp=alert_data['timestamp'],
            source_ip=alert_data['source_ip'],
            destination_ip=alert_data['destination_ip'],
            source_port=alert_data.get('source_port'),  # Use .get() to avoid KeyError if missing
            destination_port=alert_data.get('destination_port'),
            protocol=alert_data['protocol'],
            scan_type=alert_data['scan_type'],
            severity=alert_data['severity'],
            details=alert_data['details']
        )

        db_instance.session.add(new_alert)
        db_instance.session.commit()
        return True
    except Exception as e:
        print(f"LogManager: Error - Failed to save alert to database: {e}")
        db_instance.session.rollback()  # Ensure transaction is rolled back in case of error
        return False