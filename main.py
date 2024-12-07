from fastapi import FastAPI, Request
from pydantic import BaseModel
from urllib.parse import urlparse
import joblib
import tldextract
import requests
from bs4 import BeautifulSoup

app = FastAPI()

# Load the trained phishing model
model = joblib.load("phishing_model.pkl")

# Pydantic model for URL input
class URLData(BaseModel):
    url: str

# Function to extract features for prediction
def extract_features(url):
    features = {}
    features['IsHTTPS'] = int(urlparse(url).scheme == 'https')
    parsed_url = tldextract.extract(url)
    subdomain = parsed_url.subdomain
    features['NoOfSubDomain'] = subdomain.count('.') + 1 if subdomain else 0

    try:
        response = requests.get(url, timeout=5)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        features['HasFavicon'] = int(bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')))
        features['NoOfPopup'] = html_content.lower().count('window.open')
        social_sites = ['facebook', 'twitter', 'instagram']
        features['HasSocialNet'] = int(any(site in html_content.lower() for site in social_sites))
    except:
        features['HasFavicon'] = 0
        features['NoOfPopup'] = 0
        features['HasSocialNet'] = 0

    return features

# API endpoint to validate phishing URLs
@app.post("/validate")
async def validate_url(data: URLData):
    features = extract_features(data.url)
    feature_list = [list(features.values())]
    prediction = model.predict(feature_list)

    # Return prediction result
    return {
        "url": data.url,
        "status": "safe" if prediction[0] == 1 else "phishing"
    }
