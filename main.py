from fastapi import FastAPI, Form
from pydantic import BaseModel
import joblib
import re
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

    try:
        response = requests.get(url, timeout=5)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        features['HasFavicon'] = int(bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')))
        features['NoOfPopup'] = html_content.lower().count('window.open')
        social_sites = ['facebook', 'twitter', 'instagram', 'linkedin', 'youtube']
        features['HasSocialNet'] = int(any(site in html_content.lower() for site in social_sites))
        features['HasCopyrightInfo'] = int('copyright' in html_content.lower())
        features['HasDescription'] = int(bool(soup.find('meta', attrs={'name': 'description'})))
    except requests.RequestException:
        features['HasFavicon'] = 0
        features['NoOfPopup'] = 0
        features['HasSocialNet'] = 0
        features['HasCopyrightInfo'] = 0
        features['HasDescription'] = 0

    return features

@app.get("/")
def read_root():
    return {"message": "FastAPI Phishing Detection with Twilio!"}


@app.post("/sms")
async def sms_reply(Body: str = Form(...), From: str = Form(...)):
    # Extract URL from message body using regex
    url = re.findall(r'(https?://[^\s]+)', Body)
    
    if url:
        url_to_check = url[0]  # Take the first URL found
        features = extract_features(url_to_check)
        feature_list = [list(features.values())]
        prediction = model.predict(feature_list)

        # Check whether URL is phishing or legitimate
        if prediction[0] == 1:
            result = f"The URL: {url_to_check} is detected as ✅ *Legitimate* ✅. Safe to click!"
        else:
            result = f"The URL: {url_to_check} is detected as 🚨 *Phishing* 🚨. Do not click the link!"
        
        # Create Twilio response with formatted message
        response = MessagingResponse()
        response.message(result)
        return str(response)
    else:
        response = MessagingResponse()
        response.message("No URL found in the message.")
        return str(response)

    
    
