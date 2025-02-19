# Phishing URL Detector Browser Extension

## Overview
This browser extension detects phishing and legitimate URLs in real time when you visit a website. It integrates a trained machine learning model deployed using FastAPI on Render to classify URLs as phishing or legitimate. 

## Features
- **Real-time URL classification**: Automatically detects whether a website is phishing or legitimate when visited.
- **FastAPI Integration**: Sends website URLs to a FastAPI backend deployed on Render for classification.
- **Lightweight and Efficient**: Runs seamlessly in the background without affecting browser performance.

## How It Works
1. When you visit a website, the extension extracts relevant URL features.
2. The extracted data is sent to the FastAPI endpoint on Render for classification.
3. The model predicts whether the URL is phishing (`0`) or legitimate (`1`).

## Installation
### For Users:
1. Download the latest `.zip` file or clone the repository.
2. Open your browser and navigate to `chrome://extensions/` (for Chrome-based browsers).
3. Enable "Developer mode" (top-right corner).
4. Click "Load unpacked" and select the extracted extension folder.
5. The extension is now installed and active.

### For Developers:
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/phishing-url-detector-extension.git
   ```
2. Navigate to the project directory:
   ```sh
   cd phishing-url-detector-extension
   ```
3. Install dependencies (if required for local development):
   ```sh
   npm install   # If using JavaScript frameworks
   ```
4. Load the extension in your browser as described in the user installation steps.

## Configuration
### FastAPI Backend (Render Deployment)
Ensure your FastAPI application is running on Render. Update the API endpoint in `background.js` or `popup.js`:
```js
const API_URL = "https://your-fastapi-app.onrender.com/predict";
```

## Technologies Used
- **FastAPI** (Deployed on Render)
- **Machine Learning Model** (Random Forest classifier)
- **JavaScript, JSON & HTML**

## Future Enhancements
- Improve model accuracy with additional features.
- Store the phishing URLs for future analysis.
