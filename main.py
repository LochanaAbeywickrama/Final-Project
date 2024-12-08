from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup

# Load trained model using joblib
model = joblib.load("phishing_model.pkl")

app = FastAPI()

# Define a Pydantic model for URL input
class URLData(BaseModel):
    url: str

# Function to extract features from a URL (same as the one in Streamlit code)
def extract_features(url):
    features = {}

    # HTTPS Check
    features['IsHTTPS'] = int(urlparse(url).scheme == 'https')

    # Number of Subdomains
    parsed_url = tldextract.extract(url)
    subdomain = parsed_url.subdomain
    features['NoOfSubDomain'] = subdomain.count('.') + 1 if subdomain else 0

    # Attempt to fetch HTML for further analysis
    try:
        response = requests.get(url, timeout=5)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')

        # Has Favicon: Check if a favicon link is present
        features['HasFavicon'] = int(bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')))

        # Count Pop-up Windows
        features['NoOfPopup'] = html_content.lower().count('window.open')

        # Has Social Network Links: Check for common social media links
        social_sites = ['facebook', 'twitter', 'instagram', 'linkedin', 'youtube']
        features['HasSocialNet'] = int(any(site in html_content.lower() for site in social_sites))

        # Has Copyright Info: Check for "copyright" keyword
        features['HasCopyrightInfo'] = int('copyright' in html_content.lower())

        # Has Meta Description: Check for presence of meta description
        features['HasDescription'] = int(bool(soup.find('meta', attrs={'name': 'description'})))

    except requests.RequestException:
        # If the request fails, set feature values to 0
        features['HasFavicon'] = 0
        features['NoOfPopup'] = 0
        features['HasSocialNet'] = 0
        features['HasCopyrightInfo'] = 0
        features['HasDescription'] = 0

    # Return extracted features
    return features

@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI on Render!"}

# Prediction route using FastAPI
@app.post("/detect")
async def detect_url(data: URLData):
    features = extract_features(data.url)  # Extract features from the URL
    # Extract the feature set and ensure it's in the format the model expects (scaled and reshaped if needed)
    feature_list = [list(features.values())]  # Make sure it's a 2D array
    prediction = model.predict(feature_list)

    # Output both phishing and legitimate results (model trained: 1 = legitimate, 0 = phishing)
    result = {
        "legitimate": bool(prediction[0] == 1),
        "phishing": bool(prediction[0] == 0)
    }

    return result
