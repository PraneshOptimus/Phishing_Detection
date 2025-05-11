from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
import os

app = Flask(__name__)
CORS(app, resources={r"/predict": {"origins": "chrome-extension://*"}})

model = joblib.load('phishing_url_detector.pkl')

@app.route('/')
def index():
    return jsonify({'message': 'Phishing Link Detector API is running'})

def extract_features(url):
    return {
        'url_length': len(url),
        'has_at_symbol': int('@' in url),
        'has_hyphen': int('-' in url),
        'has_https': int('https' in url.lower()),
        'num_dots': url.count('.'),
        'uses_ip': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', url))),
    }

@app.route('/predict', methods=['POST'])
def predict():
    print("Received request:", request.headers)
    print("Request data:", request.data)
    try:
        data = request.get_json(force=True)
        print("Parsed JSON:", data)
    except Exception as e:
        print("JSON parsing error:", str(e))
        return jsonify({'error': 'Invalid JSON', 'details': str(e)}), 400
    if data is None:
        return jsonify({'error': 'Invalid JSON'}), 400
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0].max()
    result = 'phishing' if prediction == 1 else 'benign'
    return jsonify({
        'url': url,
        'result': result,
        'confidence': float(probability)
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 