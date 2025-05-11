Phishing Link Detector
A real-time phishing URL detection system implemented as a Chrome extension. Uses a RandomForestClassifier model to predict whether URLs are phishing or benign, with a Flask API backend.
Project Structure

model-development/: Scripts and dataset for training the ML model.
backend/: Flask API to serve the phishing detection model.
chrome-extension/: Chrome extension for real-time URL checking.

Setup
Model Development

Navigate to model-development/.
Install dependencies: pip install -r requirements.txt.
Place your dataset as datasets.csv.
Run: python train_model.py to generate phishing_url_detector.pkl.
Copy the model to backend/:cp model-development/phishing_url_detector.pkl backend/



Backend

Navigate to backend/.
Install dependencies: pip install -r requirements.txt.
Run the API: python api.py.
Deploy to Heroku (optional):
Create a Heroku app: heroku create.
Push to Heroku: git push heroku main.



Chrome Extension

Open Chrome and go to chrome://extensions/.
Enable "Developer mode".
Click "Load unpacked" and select the chrome-extension/ folder.
Update the API URL in background.js to your deployed API.

Usage

Click the extension icon to view the current page’s URL status and suspicious links.
Report false positives using the popup button.

License
MIT
