# ids_system_complete.py
# Complete Intrusion Detection System Implementation

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import warnings
warnings.filterwarnings('ignore')


class IntrusionDetectionSystem:
    """
    Intrusion Detection System using Random Forest Classifier
    Trained on CICIDS2017-like dataset features
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None

    def prepare_data(self, df):
        """
        Prepare and clean the dataset

        Parameters:
        -----------
        df : pandas.DataFrame
            DataFrame containing features and Label column

        Returns:
        --------
        X_scaled : numpy.ndarray
            Scaled feature matrix
        y : pandas.Series
            Binary labels (0=BENIGN, 1=ATTACK)
        """
        print("Preparing data...")

        # Remove infinite and NaN values
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna()

        # Separate features and target
        X = df.drop(['Label'], axis=1)
        y = df['Label']

        # Convert labels to binary (BENIGN vs Attack)
        y = y.apply(lambda x: 0 if x == 'BENIGN' else 1)

        print(f"Features shape: {X.shape}")
        print(f"Class distribution:")
        print(f"  BENIGN: {(y == 0).sum()}")
        print(f"  ATTACK: {(y == 1).sum()}")

        # Store feature names
        self.feature_names = X.columns.tolist()

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled, y

    def train_model(self, X_train, y_train):
        """
        Train the Random Forest model
        """
        print("\nTraining Random Forest model...")
        print("Model parameters:")
        print("  - n_estimators: 100")
        print("  - max_depth: 20")
        print("  - random_state: 42")

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
            verbose=0
        )

        self.model.fit(X_train, y_train)
        print("✓ Model training completed!")

    def evaluate_model(self, X_test, y_test):
        """
        Evaluate the model performance
        """
        print("\nEvaluating model performance...")

        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"\n{'='*50}")
        print(f"MODEL PERFORMANCE")
        print(f"{'='*50}")
        print(f"\nAccuracy: {accuracy*100:.2f}%")
        print("\nClassification Report:")
        print(classification_report(
            y_test,
            y_pred,
            target_names=['BENIGN', 'ATTACK'],
            digits=4
        ))

        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"              BENIGN  ATTACK")
        print(f"Actual BENIGN  {cm[0][0]:6d}  {cm[0][1]:6d}")
        print(f"       ATTACK  {cm[1][0]:6d}  {cm[1][1]:6d}")

        return accuracy, y_pred

    def predict(self, features):
        """
        Predict if traffic is normal or attack
        """
        if self.model is None:
            raise Exception("Model not trained. Please train the model first.")

        features = np.array(features).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)
        probability = self.model.predict_proba(features_scaled)

        return int(prediction[0]), probability[0]

    def save_model(self, filename='ids_model.pkl'):
        """
        Save the trained model to disk
        """
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }

        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"\n✓ Model saved as '{filename}'")

    def load_model(self, filename='ids_model.pkl'):
        """
        Load a trained model from disk
        """
        try:
            with open(filename, 'rb') as f:
                model_data = pickle.load(f)

            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']

            print(f"✓ Model loaded from '{filename}'")
            print(f"✓ Features: {len(self.feature_names)}")

        except FileNotFoundError:
            print(f"✗ Error: Model file '{filename}' not found")
            raise
