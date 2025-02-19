from fastapi import FastAPI, Request
from pydantic import BaseModel
import joblib
import mysql.connector
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import datetime

# Load trained model
model = joblib.load("random_forest_model.pkl")

app = FastAPI()

# Define URL input model
class URLData(BaseModel):
    url: str

# Feature Extraction Function
def extract_features(url):
    features = {}

    # HTTPS Check
    features['IsHTTPS'] = int(urlparse(url).scheme == 'https')

    try:
        response = requests.get(url, timeout=5)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')

        # Check for social media links
        social_sites = ['facebook', 'twitter', 'instagram', 'linkedin', 'youtube']
        features['HasSocialNet'] = int(any(site in html_content.lower() for site in social_sites))

        # Check for copyright info
        features['HasCopyrightInfo'] = int('copyright' in html_content.lower())

        # Check for meta description
        features['HasDescription'] = int(bool(soup.find('meta', attrs={'name': 'description'})))

    except requests.RequestException:
        features['HasSocialNet'] = 0
        features['HasCopyrightInfo'] = 0
        features['HasDescription'] = 0

    return features

@app.get("/")
def read_root():
    return {"message": "FastAPI Honeypot-Based Phishing Detector Running!"}

# Prediction Route
@app.post("/detect")
async def detect_url(data: URLData, request: Request):
    features = extract_features(data.url)
    feature_list = [list(features.values())]  # Convert to 2D array
    prediction = model.predict(feature_list)

    result = {
        "legitimate": bool(prediction[0] == 1),
        "phishing": bool(prediction[0] == 0),
        "url": data.url
    }

    return result  


