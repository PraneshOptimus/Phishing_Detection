import pandas as pd
import re
import logging
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_features(url):
    """Extract features from a URL."""
    return {
        'url_length': len(url),
        'has_at_symbol': int('@' in url),
        'has_hyphen': int('-' in url),
        'has_https': int('https' in url.lower()),
        'num_dots': url.count('.'),
        'uses_ip': int(bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', url))),
        'subdomain_count': len(url.split('.')[0].split('.')) - 1,
        'has_suspicious_keyword': int(any(k in url.lower() for k in ['login', 'verify', 'bank']))
    }

def preprocess_dataset(file_path):
    """Preprocess the dataset and extract features."""
    if not os.path.exists(file_path):
        logging.error("File %s not found.", file_path)
        return None

    try:
        data = pd.read_csv(file_path, on_bad_lines='skip')
        data.columns = data.columns.str.strip().str.lower()
        logging.info("Columns in the dataset: %s", data.columns)

        if 'url' not in data.columns or 'label' not in data.columns:
            logging.error("Required columns ('url', 'label') not found.")
            return None

        data.dropna(inplace=True)
        data.drop_duplicates(inplace=True)
        if data.empty:
            logging.error("Dataset is empty after preprocessing.")
            return None

        features = data['url'].apply(extract_features)
        features_df = pd.DataFrame(features.tolist())
        processed_data = pd.concat([features_df, data['label']], axis=1)
        return processed_data
    except pd.errors.ParserError as e:
        logging.error("Error reading CSV file: %s", e)
        return None

def main():
    dataset_path = "csv/datasets.csv"
    dataset = preprocess_dataset(dataset_path)

    if dataset is not None:
        logging.info("Sample features:\n%s", dataset.head())

        # Encode labels if necessary
        le = LabelEncoder()
        dataset['label'] = le.fit_transform(dataset['label'])

        X = dataset.drop('label', axis=1)
        y = dataset['label']
        logging.info("Class distribution:\n%s", pd.Series(y).value_counts())

        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Model training
        model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        model.fit(X_train, y_train)

        # Cross-validation
        cv_scores = cross_val_score(model, X, y, cv=5, scoring='f1')
        logging.info("Cross-Validation F1 Scores: %s, Mean: %.3f", cv_scores, cv_scores.mean())

        # Evaluation
        y_pred = model.predict(X_test)
        logging.info("Accuracy: %.3f", accuracy_score(y_test, y_pred))
        logging.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))
        logging.info("Classification Report:\n%s", classification_report(y_test, y_pred))

        # Save model
        joblib.dump(model, 'phishing_url_detector.pkl')
        logging.info("Model saved to phishing_url_detector.pkl")
    else:
        logging.error("Dataset preprocessing failed. Exiting.")

if __name__ == "__main__":
    main()