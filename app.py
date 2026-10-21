import streamlit as st
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import whois
from datetime import datetime
import dns.resolver
import requests
from bs4 import BeautifulSoup
import joblib
import requests
def check_google_index(domain):
    try:
        query = f"https://www.google.com/search?q=site:{domain}"
        response = requests.get(query, timeout=5, headers={"User-Agent":"Mozilla/5.0"})
        if "did not match any documents" in response.text:
            return -1  # not indexed
        return 1       # indexed
    except:
        return -1
def check_links_pointing(domain):
    # Placeholder: assume popular domains have backlinks
    if domain in ["microsoft.com","amazon.com","google.com","paypal.com"]:
        return 1
    return -1


def get_web_traffic(domain):
    try:
        # Example API call (replace with real API key/service)
        response = requests.get(f"https://api.similarweb.com/v1/website/{domain}/traffic", timeout=5)
        data = response.json()
        visits = data.get("visits", 0)
        return 1 if visits > 10000 else -1
    except:
        return -1


# Load dataset
df = pd.read_csv("phishing.csv")

# Train only on features you can extract now
usable_features = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'HTTPS_token',
    'Suspicious_Keywords',
    'age_of_domain',
    'Domain_registration_length',
    'DNSRecord',
    'Favicon',
    'Iframe',
    'popUpWindow',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page'
]
# Add dummy columns for new features if not present in dataset
for col in usable_features:
    if col not in df.columns:
        df[col] = -1


X = df[usable_features]
y = df['Result']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model for reuse
joblib.dump(model, "phishing_model.pkl")


# -----------------------------
# Feature extraction from URL
# -----------------------------
def extract_features(url):
    features = {}
    parsed = urlparse(url)

    # Existing features...
    features['having_IP_Address'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc) else -1
    features['URL_Length'] = 1 if len(url) >= 54 else -1
    features['Shortining_Service'] = 1 if any(s in url for s in ["bit.ly","tinyurl","goo.gl"]) else -1
    features['having_At_Symbol'] = 1 if '@' in url else -1
    features['double_slash_redirecting'] = 1 if '//' in url[7:] else -1
    features['Prefix_Suffix'] = 1 if '-' in parsed.netloc else -1
    features['having_Sub_Domain'] = 1 if parsed.netloc.count('.') > 2 else -1
    features['SSLfinal_State'] = 1 if url.startswith("https://") else -1
    features['HTTPS_token'] = 1 if 'https' in parsed.netloc else -1
    features['Suspicious_Keywords'] = 1 if any(k in url.lower() for k in ["login","verify","update","secure","account"]) else -1

    # WHOIS checks
    try:
        domain_info = whois.whois(parsed.netloc)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):  # sometimes WHOIS returns a list
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            age_days = (datetime.now() - creation_date).days
            reg_length_days = (expiration_date - creation_date).days

            # age_of_domain: phishing sites often < 180 days old
            features['age_of_domain'] = 1 if age_days >= 180 else -1

            # Domain_registration_length: long registration is safer
            features['Domain_registration_length'] = 1 if reg_length_days >= 365 else -1
        else:
            features['age_of_domain'] = -1
            features['Domain_registration_length'] = -1
    except Exception:
        features['age_of_domain'] = -1
        features['Domain_registration_length'] = -1
    try:
        dns.resolver.resolve(parsed.netloc, 'A')
        features['DNSRecord'] = 1   # DNS record exists → safer
    except Exception:
        features['DNSRecord'] = -1  # No DNS record → suspicious
    # Web traffic & Page Rank
    features['web_traffic'] = get_web_traffic(parsed.netloc)
    features['Page_Rank'] = 1 if features['web_traffic'] == 1 else -1
    features['Google_Index'] = check_google_index(parsed.netloc)
    features['Links_pointing_to_page'] = check_links_pointing(parsed.netloc)


    # HTML content checks
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # Favicon check
        favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        features['Favicon'] = 1 if favicon else -1

        # Iframe check
        iframe = soup.find("iframe")
        features['Iframe'] = -1 if iframe else 1  # presence of iframe = suspicious

        # Pop-up check (basic: look for window.open in scripts)
        features['popUpWindow'] = -1 if "window.open" in html else 1

    except Exception:
        features['Favicon'] = -1
        features['Iframe'] = -1
        features['popUpWindow'] = -1

    sample = pd.DataFrame([features])
    sample = sample.reindex(columns=X.columns, fill_value=-1)
    return sample

# -----------------------------
# Streamlit UI
# -----------------------------
import streamlit as st

st.title("🔐 Phishing Website Detector")

url = st.text_input("Enter a website URL:")
if url:
    model = joblib.load("phishing_model.pkl")  # load saved model
    sample = extract_features(url)
    prediction = model.predict(sample)

    if prediction[0] == 1:
        st.error("🚨 Phishing Website Detected!")
    else:
        st.success("✅ Legitimate Website")



