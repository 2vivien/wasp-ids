import pandas as pd
from supervised.automl import AutoML
from datetime import datetime, timezone
import json
import os

# Define the results path for MLJAR outputs
RESULTS_PATH = "mljar_results"
CONFIG_FILE = "anomaly_detection_config.json"

def train_model():
    print("Starting training...")

    # Load data
    try:
        data = pd.read_csv("training_data.csv")
    except FileNotFoundError:
        print("Error: training_data.csv not found. Make sure the file is in the project root.")
        return
    except Exception as e:
        print(f"Error loading training_data.csv: {e}")
        return

    if 'is_anomaly' not in data.columns:
        print("Error: 'is_anomaly' column not found in training_data.csv.")
        return

    X = data.drop('is_anomaly', axis=1)
    y = data['is_anomaly']

    # Initialize AutoML
    # Using 'Perform' mode for this task as specified.
    # Consider 'Explain' mode for more detailed explanations if needed later.
    automl = AutoML(results_path=RESULTS_PATH, mode="Perform", total_time_limit=60) # Reduced time limit for faster execution

    print("Training AutoML model...")
    try:
        automl.fit(X, y)
        print("Training complete.")
    except Exception as e:
        print(f"Error during AutoML training: {e}")
        return

    # Attempt to get feature importances
    feature_importances_df = None
    try:
        # The exact method to get feature importances might vary based on MLJAR version
        # and chosen algorithms. We look for common report files.
        # First, try to get it directly if the object supports it (less common for full AutoML).
        # For many cases, we need to parse reports from the results_path.
        
        # Let's check for leaderboard.csv which often contains model performance and paths to specific model reports
        leaderboard_path = os.path.join(RESULTS_PATH, "leaderboard.csv")
        if os.path.exists(leaderboard_path):
            leaderboard = pd.read_csv(leaderboard_path)
            if not leaderboard.empty:
                # Get the best model's name (often in 'name' or 'model_type' column)
                best_model_name = leaderboard.iloc[0].get('name', leaderboard.iloc[0].get('model_type'))
                if best_model_name:
                    # Path to the specific model's feature importance, often in a subfolder
                    # Example path: mljar_results/Model_Name/learner_1_fold_0_importance.csv
                    # This is a guess, actual path might differ.
                    # We will try to find a common pattern for importance files.
                    importance_file_pattern = "importance.csv" # Common suffix
                    for root, dirs, files in os.walk(RESULTS_PATH):
                        for file in files:
                            if best_model_name in root and file.endswith(importance_file_pattern) and "learner" in file:
                                importance_path = os.path.join(root, file)
                                print(f"Found importance file: {importance_path}")
                                feature_importances_df = pd.read_csv(importance_path)
                                break
                        if feature_importances_df is not None:
                            break
                    if feature_importances_df is None:
                         print(f"Could not automatically find feature importance file for model {best_model_name}. MLJAR results are saved in {RESULTS_PATH}.")

        if feature_importances_df is not None and 'feature' in feature_importances_df.columns and 'importance' in feature_importances_df.columns:
            importances = pd.Series(feature_importances_df.importance.values, index=feature_importances_df.feature).to_dict()
        else:
            print("Feature importance data frame is not in the expected format or not found. Saving MLJAR results path instead.")
            importances = {"message": f"Feature importances not directly extracted. Check MLJAR reports in '{RESULTS_PATH}'."}

    except Exception as e:
        print(f"Could not extract feature importances: {e}. MLJAR results are saved in {RESULTS_PATH}.")
        importances = {"message": f"Error extracting feature importances: {e}. Check MLJAR reports in '{RESULTS_PATH}'."}

    # Prepare data for JSON
    config_data = {
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "mljar_results_path": os.path.abspath(RESULTS_PATH) # Save absolute path for clarity
    }
    if isinstance(importances, dict) and "message" not in importances:
         config_data["feature_importances"] = importances
    else:
        config_data["feature_importance_status"] = importances.get("message", "Extraction failed or not available.")


    # Save to JSON
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=4)
        print(f"Configuration and MLJAR results path saved to {CONFIG_FILE}")
    except Exception as e:
        print(f"Error saving configuration to {CONFIG_FILE}: {e}")

if __name__ == '__main__':
    # Create results directory if it doesn't exist
    if not os.path.exists(RESULTS_PATH):
        os.makedirs(RESULTS_PATH)
    train_model()
