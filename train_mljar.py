import pandas as pd
from supervised.automl import AutoML
import argparse
import os

def train_model(csv_path, results_path):
    if not os.path.exists(csv_path):
        print(f"Error: Dataset CSV file not found at {csv_path}")
        return

    print(f"Loading dataset from: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error loading CSV file: {e}")
        return

    if df.empty:
        print("Error: Dataset is empty.")
        return
    
    if df.shape[1] < 2:
        print("Error: Dataset must have at least two columns (features and a target).")
        return

    # Assuming the last column is the target variable
    X = df.iloc[:, :-1]
    y = df.iloc[:, -1]

    print(f"Features: {X.columns.tolist()}")
    print(f"Target column assumed to be: {df.columns[-1]}")

    # Create results directory if it doesn't exist
    if not os.path.exists(results_path):
        try:
            os.makedirs(results_path)
            print(f"Created results directory: {results_path}")
        except Exception as e:
            print(f"Error creating results directory {results_path}: {e}")
            return

    automl = AutoML(
        results_path=results_path,
        total_time_limit=300, # 5 minutes for a quick run, can be increased
        mode="Explain", # Focus on explainability
        algorithms=["Decision Tree", "Random Forest", "Xgboost"], # Added some interpretable models
        explain_level=2, # Higher level for more explanations
        random_state=123 # for reproducibility
    )

    print("Starting MLJAR AutoML training...")
    try:
        automl.fit(X, y)
        print(f"Training complete. Results saved to: {results_path}")
    except Exception as e:
        print(f"Error during AutoML training: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train a model using MLJAR AutoML.")
    parser.add_argument('--csv_path', type=str, default='network_traffic_dataset.csv', 
                        help='Path to the input CSV dataset.')
    parser.add_argument('--results_path', type=str, default='mljar_model_output',
                        help='Path to save MLJAR results.')
    
    args = parser.parse_args()
            
    train_model(args.csv_path, args.results_path)
