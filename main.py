from fastapi import FastAPI, Form
from pydantic import BaseModel
import joblib
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
from twilio.twiml.messaging_response import MessagingResponse

# Load trained model
model = joblib.load("phishing_model.pkl")

app = FastAPI()

# Function to extract features from a URL
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

        # Has Favicon
        features['HasFavicon'] = int(bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')))
        features['NoOfPopup'] = html_content.lower().count('window.open')
        social_sites = ['facebook', 'twitter', 'instagram', 'linkedin', 'youtube']
        features['HasSocialNet'] = int(any(site in html_content.lower() for site in social_sites))
        features['HasCopyrightInfo'] = int('copyright' in html_content.lower())
        features['HasDescription'] = int(bool(soup.find('meta', attrs={'name': 'description'})))

    except requests.RequestException:
        # Request failed
        features['HasFavicon'] = 0
        features['NoOfPopup'] = 0
        features['HasSocialNet'] = 0
        features['HasCopyrightInfo'] = 0
        features['HasDescription'] = 0

    return features

@app.post("/sms-webhook")
async def sms_webhook(From: str = Form(...), Body: str = Form(...)):
    """
    Twilio will send SMS data here. We extract any URL from the message and predict phishing.
    """
    # Extract URL from message body
    import re
    url_match = re.search(r'https?://\S+', Body)
    if not url_match:
        # If no URL is found
        response = MessagingResponse()
        response.message("No URL detected in the message.")
        return str(response)

    url = url_match.group(0)

    # Extract features and predict
    features = extract_features(url)
    feature_list = [list(features.values())]
    prediction = model.predict(feature_list)

    # Determine result
    if prediction[0] == 1:
        result = "Legitimate URL ✅"
    else:
        result = "Phishing URL 🚨"

    # Respond to sender via Twilio
    response = MessagingResponse()
    response.message(f"The detected URL: {url}\nResult: {result}")
    return str(response)

@app.get("/")
def read_root():
    return {"message": "FastAPI Phishing Detection with Twilio!"}
